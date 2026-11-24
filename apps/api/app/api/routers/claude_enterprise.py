"""Tenant-bound Enterprise inference hook. Disabled until operator provisioning."""
import hashlib
import json
import os
from pathlib import Path
import re
from uuid import UUID

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from app.services.native_control.claude_enterprise_inference import MAX_BODY, deny, verify_frame, verdict_for_frame

router = APIRouter(prefix='/native-controls/claude-enterprise', tags=['native-controls'])


def load_binding(integration_id):
    if not re.fullmatch(r'[a-z0-9-]{1,64}', integration_id):
        raise ValueError('invalid integration')
    path = Path(os.environ.get('HAWK_CLAUDE_ENTERPRISE_BINDINGS_FILE', ''))
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or path.stat().st_mode & 0o077 or path.stat().st_size > 262144):
        raise ValueError('integration is not provisioned')
    binding = json.loads(path.read_text())[integration_id]
    if binding.get('enabled') is not True:
        raise ValueError('integration is disabled')
    for field in ('organization_id', 'tenant_id', 'ai_system_id'):
        if str(UUID(binding[field])) != binding[field] or UUID(binding[field]).int == 0:
            raise ValueError('invalid integration binding')
    refs = binding.get('secret_envs')
    if not isinstance(refs, list) or not 1 <= len(refs) <= 2:
        raise ValueError('signing secret reference required')
    if any(not isinstance(ref, str) or not re.fullmatch(r'HAWK_CLAUDE_HOOK_SECRET_[A-Z0-9_]+', ref) for ref in refs):
        raise ValueError('invalid secret reference')
    secrets = [os.environ[ref] for ref in refs]
    return {**binding, 'secrets': secrets}


def claim_delivery(binding, event_id):
    from redis import Redis
    from app.core.config import settings
    digest = hashlib.sha256((binding['tenant_id'] + ':' + binding['organization_id'] + ':' + event_id).encode()).hexdigest()
    with Redis.from_url(settings.redis_url, socket_connect_timeout=0.5, socket_timeout=0.5) as client:
        # Duplicate deliveries deny rather than reusing potentially stale allows.
        return bool(client.set('hawk:claude-inference:' + digest, 'claimed', nx=True, ex=610))


def evaluate_policy(binding, frame):
    from app.core.config import settings
    from app.db.session import SessionLocal
    from app.db.models.tenant import Tenant
    from app.services.gateway_service import llm_intercept
    from app.services.fail_secure_service import enforce_fail_secure_or_raise
    from app.services.rate_limit_service import tenant_rate_limiter
    from app.services.audit_service import write_audit_log

    with SessionLocal() as db:
        try:
            tenant = db.get(Tenant, binding['tenant_id'])
            if (tenant is None or not tenant.is_active or tenant.platform_mode != 'enforce'
                    or settings.gateway_intercept_minimal_mode):
                return deny()
            req_id = 'claude-hook-' + hashlib.sha256((binding['organization_id'] + ':' + frame['request_id']).encode()).hexdigest()
            enforce_fail_secure_or_raise(db, tenant_id=tenant.id, module='gateway',
                ai_system_id=binding['ai_system_id'], request_id=req_id)
            allowed, _ = tenant_rate_limiter.check_and_consume(route_key='claude.enterprise.inference',
                tenant_id=tenant.id, qps_limit=settings.llm_intercept_qps_per_tenant,
                window_seconds=settings.rate_limit_window_seconds)
            if not allowed:
                return deny()
            actor = frame.get('actor') or {}
            if not isinstance(actor, dict):
                return deny()
            actor_id = hashlib.sha256(str(actor.get('id') or 'unknown').encode()).hexdigest()

            def inspect(transcript):
                result = llm_intercept(db, tenant_id=tenant.id, ai_system_id=binding['ai_system_id'],
                    actor_type='human', actor_id=actor_id, request_id=req_id, prompt=transcript,
                    context_summary='Claude Enterprise pre-inference transcript', attachments_meta=[],
                    tool_output=None, audit_actor_user_id=None, provider='anthropic',
                    model_name=frame.get('model'), data_source='claude_enterprise_inference_hook')
                if result.get('platform_mode') != 'enforce':
                    return {'final_decision': 'block'}
                return result

            verdict = verdict_for_frame(frame, inspect)
            reference = hashlib.sha256(req_id.encode()).hexdigest()[:40]
            write_audit_log(db, tenant_id=tenant.id, actor_user_id=None, actor_type='system',
                action='claude.enterprise.inference.verdict', resource_type='ai_system',
                resource_id=binding['ai_system_id'], correlation_id=req_id,
                payload={'action': verdict['action'], 'reference_id': reference,
                         'boundary': 'after_provider_receipt_before_inference'})
            db.commit()
            if verdict['action'] == 'deny':
                verdict['reference_id'] = reference
            return verdict
        except Exception:
            db.rollback()
            return deny()


@router.post('/{integration_id}/inference')
async def inference(integration_id: str, request: Request):
    # Do not put signature failures through exception handlers that might log bodies.
    try:
        if request.headers.get('content-encoding', 'identity').lower() != 'identity':
            return deny()
        for name in ('webhook-id', 'webhook-timestamp', 'webhook-signature'):
            if len(request.headers.getlist(name)) != 1:
                return deny()
        binding = load_binding(integration_id)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_BODY:
                return deny('Request exceeds Hawk inspection capacity.')
            body.extend(chunk)
        frame = verify_frame(bytes(body), request.headers, binding['secrets'], binding['organization_id'])
        if not await run_in_threadpool(claim_delivery, binding, frame['request_id']):
            return deny()
        return await run_in_threadpool(evaluate_policy, binding, frame)
    except Exception:
        return deny()
