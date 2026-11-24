#!/usr/bin/env python3
"""Interactive local gateway test. Credentials stay in process memory."""
import argparse
import getpass
import json
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.request
import uuid


def system_label(row):
    metadata = row.get("metadata_json") or {}
    details = [f"stored status: {row['status']}"]
    if metadata.get("ownership_state") in {"UNKNOWN", "MISSING"}:
        details.append("ownership unresolved — governance review required")
    if metadata.get("compliance_state") == "NON_COMPLIANT":
        details.append("non-compliant — governance review required")
    return f"{row['name']} [{'; '.join(details)}]"


def choose(label, rows, display):
    if not rows:
        raise RuntimeError(f"No {label} available. Configure this in Hawk first.")
    print(f"\nSelect {label}:")
    for index, row in enumerate(rows, 1):
        print(f"  {index}. {display(row)}")
    while True:
        value = input("Number or ID" + (" [1]" if len(rows) == 1 else "") + ": ").strip()
        if not value and len(rows) == 1:
            return rows[0]
        for row in rows:
            if value == row.get("id"):
                return row
        if value.isdigit() and 1 <= int(value) <= len(rows):
            return rows[int(value) - 1]
        print(f"Choose a number from 1 to {len(rows)}, or paste the exact ID.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="qwen3.5:9b")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    context = ssl.create_default_context(cafile=str(root / "infra/tls/local/hawk-local.crt"))
    base = "https://api.hawk.localhost:3444"
    # Refuse redirects so credentials cannot leave the fixed local test service.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )
    headers = {"Content-Type": "application/json"}

    def call(path, payload=None):
        request = urllib.request.Request(
            base + path, headers=headers,
            data=None if payload is None else json.dumps(payload).encode(),
        )
        try:
            with opener.open(request, timeout=240) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            try:
                detail = json.load(exc).get("detail", {})
            except (ValueError, AttributeError):
                detail = {}
            codes = {k: detail[k] for k in ("code", "reason_code", "failed_checks", "audit_log_id") if k in detail} if isinstance(detail, dict) else {}
            raise RuntimeError(f"HTTP {exc.code}: {codes or 'request rejected; check Hawk activity logs'}") from None

    def all_rows(path):
        rows, page = [], 1
        while True:
            result = call(f"{path}?page={page}&page_size=50")
            batch = result["items"]
            rows.extend(batch)
            if not batch or len(rows) >= result["total"]:
                return rows
            page += 1

    print("Hawk local LLM gateway → Ollama. Use synthetic test data only.")
    print("Normal Hawk authentication and policy checks remain enabled.")
    email = input("Hawk email: ").strip()
    password = getpass.getpass("Hawk password (hidden): ")
    login = call("/auth/login", {"email": email, "password": password})
    del password
    headers["Authorization"] = "Bearer " + login["access_token"]
    tenant = choose("tenant", login["tenants"], lambda r: f"{r['name']} ({r['role']})")
    selected = call("/auth/select-tenant", {"tenant_id": tenant["id"]})
    headers["Authorization"] = "Bearer " + selected["access_token"]
    headers["X-Tenant-ID"] = tenant["id"]
    actor_id = login["user"]["id"]
    del login, selected
    call("/llm-gateway/config")
    print("\nSelect the application being tested, not the model vendor.")
    print("The model for this session is Ollama. Stored status alone is not runtime approval.")
    systems = all_rows("/ai-systems")
    system = choose("AI system", systems, system_label)
    pack = choose("policy pack", all_rows("/policies/packs"), lambda r: r["name"])
    policy = choose("policy version", all_rows(f"/policies/packs/{pack['id']}/versions"), lambda r: f"{r['version']} ({r['id']})")
    print("\nType a prompt to run the actual gateway. /system changes the AI system; /quit exits.")
    print("Each request creates normal Hawk activity/evidence. No policies are changed.")
    while True:
        prompt = input("\nPrompt: ").strip()
        if prompt == "/quit":
            return
        if prompt == "/system":
            systems = all_rows("/ai-systems")
            system = choose("AI system", systems, system_label)
            continue
        if not prompt:
            continue
        payload = {
            "tenant_id": tenant["id"], "ai_system_id": system["id"],
            "policy_version_id": policy["id"], "actor_id": actor_id,
            "actor_type": "human", "provider": "ollama", "model": args.model,
            "request_id": "manual-llm-" + uuid.uuid4().hex,
            "system_prompt": "Answer concisely. Do not include private reasoning.",
            "messages": [{"role": "user", "content": prompt}],
        }
        try:
            result = call("/llm-gateway/chat/complete", payload)
        except RuntimeError as exc:
            print(f"Request not completed: {exc}")
            print("No success is assumed. Use /system to change context, or /quit.")
            continue
        print(json.dumps({k: result.get(k) for k in (
            "final_decision", "provider_invoked", "response_control_coverage",
            "event_id", "request_id", "evidence_node_ids",
        )}, indent=2))
        print("Answer:", result.get("completion") or "[No answer released]")
        for guardian in result.get("guardian_results", []):
            if guardian.get("decision") != "allow":
                print("Policy:", guardian.get("guardian_id"), guardian.get("decision"), guardian.get("reason"))


if __name__ == "__main__":
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print("\nExited.")
    except (RuntimeError, urllib.error.URLError, TimeoutError) as exc:
        print(f"Test stopped: {exc}", file=sys.stderr)
        sys.exit(1)
