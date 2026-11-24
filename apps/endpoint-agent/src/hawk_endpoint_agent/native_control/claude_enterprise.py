"""Deployment artifacts; generating them is not evidence of active enforcement."""
import json
import plistlib
import re
from uuid import UUID, uuid5, NAMESPACE_URL

HOSTS = ('claude.ai', 'api.anthropic.com', 'claude.com', 'anthropic.com')
HEADER = 'anthropic-allowed-org-ids'


def organization_ids(values):
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= 500:
        raise ValueError('one to 500 organization UUIDs required')
    ids = list(dict.fromkeys(str(UUID(value)) for value in values))
    if any(UUID(value).int == 0 for value in ids):
        raise ValueError('nil organization UUID is not allowed')
    return ids


def restriction_headers(host, headers, org_ids):
    ids = organization_ids(org_ids)
    if host.lower() not in HOSTS:
        return list(headers)
    clean = [(key, value) for key, value in headers
             if not re.fullmatch(HEADER + r'\d*', key.lower())]
    chunks = [','.join(ids[index:index + 50]) for index in range(0, len(ids), 50)]
    for index, chunk in enumerate(chunks):
        suffix = '' if index == 0 else str(index)
        if index == 0 and len(chunks) > 1:
            chunk += ';n=' + str(len(chunks))
        clean.append((HEADER + suffix, chunk))
    return clean


def deployment_bundle(org_ids):
    ids = organization_ids(org_ids)
    identifier = 'ai.hawk.claude.organization.' + str(uuid5(NAMESPACE_URL, ','.join(ids)))
    profile = {
        'PayloadType': 'Configuration', 'PayloadVersion': 1,
        'PayloadIdentifier': identifier, 'PayloadUUID': str(uuid5(NAMESPACE_URL, identifier)),
        'PayloadDisplayName': 'Hawk Claude organization restriction', 'PayloadScope': 'System',
        'PayloadContent': [{
            'PayloadType': 'com.anthropic.claudefordesktop', 'PayloadVersion': 1,
            'PayloadIdentifier': identifier + '.preferences',
            'PayloadUUID': str(uuid5(NAMESPACE_URL, identifier + '.preferences')),
            'forceLoginOrgUUID': ids[0] if len(ids) == 1 else ids,
        }],
    }
    addon = '''# Deploy in your managed mitmproxy TLS inspection path with the Hawk package installed.
# Does not create mandatory routing or trust. Does not inspect message content.
from hawk_endpoint_agent.native_control.claude_enterprise import HOSTS, restriction_headers
ORG_IDS = ''' + repr(ids) + '''

def request(flow):
    if flow.request.host.lower() not in HOSTS:
        return
    if flow.request.scheme != 'https':
        from mitmproxy import http
        flow.response = http.Response.make(403, b'Hawk requires managed HTTPS inspection')
        return
    pairs = restriction_headers(flow.request.host, flow.request.headers.items(multi=True), ORG_IDS)
    flow.request.headers.clear()
    for name, value in pairs:
        flow.request.headers.add(name, value)
'''
    return {
        'claude.mobileconfig': plistlib.dumps(profile).decode(),
        # Windows uses a documented single string. Multi-org login profiles need
        # vendor/MDM-specific array encoding; do not invent a registry encoding.
        'claude-windows.reg': 'Windows Registry Editor Version 5.00\n\n'
            '; Login restricted to the primary (first) approved organization.\n'
            '[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Claude]\n'
            '"forceLoginOrgUUID"="' + ids[0] + '"\n',
        'claude-tenant-restriction.py': addon,
        'deployment.json': json.dumps({
            'schema': 'hawk.claude-enterprise-boundary/1', 'status': 'unverified',
            'organization_ids': ids, 'windows_login_organization': ids[0],
            'proxy_hosts': HOSTS, 'proxy_headers': restriction_headers('claude.ai', [], ids),
            'tls_inspection_required': True, 'mandatory_routing_required': True,
            'personal_chat_content_inspection': False,
            'inference_requirements': {'failure_handling': 'block', 'rollout_percent': 100,
                                     'enforce_verdicts': True, 'shadow_mode': False,
                                     'role_exclusions': []},
            'acceptance_required': ['managed_preferences_applied', 'existing_session_and_account_switch',
                'approved_org_allow', 'personal_org_deny', 'off_network_and_direct_route_deny',
                'signed_inference_allow_deny', 'inference_outage_deny'],
        }, indent=2) + '\n',
    }
