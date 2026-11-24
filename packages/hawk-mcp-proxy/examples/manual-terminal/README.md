# Manual Terminal MCP Inline-Control Proof

This local lab lets you personally invoke one harmless MCP tool through the real
Hawk MCP proxy. It is not a guided demo pack.

The manual client explicitly uses the proxy's legacy `content-length` framing
so its existing proof flow remains stable. Codex integrations use the proxy's
default NDJSON framing instead.

The proof scenario deliberately supplies invalid session and capability
authority. Success means Hawk persists a block, the proxy withholds the call,
and the child server does not write its fixed marker.

## 1. Verify the local stack

Run these commands from the Hawk repository root:

```zsh
curl --fail --silent http://127.0.0.1:8000/health
curl --fail --silent http://localhost:3001/login >/dev/null
```

The UI is at [http://localhost:3001](http://localhost:3001). The API used by
this lab is `http://127.0.0.1:8000`.

## 2. Sign in without exposing the password or token

```zsh
export HAWK_API_URL="http://127.0.0.1:8000"
export HAWK_EMAIL="owner@acme.ai"
read -s "HAWK_PASSWORD?Hawk password: "
echo
export HAWK_PASSWORD
HAWK_ACCESS_TOKEN="$(node --input-type=module -e 'const response = await fetch(`${process.env.HAWK_API_URL}/auth/login`, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({email:process.env.HAWK_EMAIL,password:process.env.HAWK_PASSWORD})}); if(!response.ok) process.exit(1); const body=await response.json(); process.stdout.write(body.access_token);')"
export HAWK_ACCESS_TOKEN
unset HAWK_PASSWORD
```

Verify the tenant memberships without printing the token:

```zsh
node --input-type=module -e 'const response=await fetch(`${process.env.HAWK_API_URL}/auth/me`,{headers:{Authorization:`Bearer ${process.env.HAWK_ACCESS_TOKEN}`}}); if(!response.ok) process.exit(1); const body=await response.json(); console.table(body.tenants.map(({id,name,role})=>({id,name,role})));'
```

The current local demo tenant is expected to be
`9300801c-8597-4813-ad44-ddc5a88ec5a6`, but use the membership output above as
the authority:

```zsh
export HAWK_TENANT_ID="9300801c-8597-4813-ad44-ddc5a88ec5a6"
```

List AI systems and select a tenant system that is active, governance-approved,
in an active lifecycle, and not missing ownership:

```zsh
node --input-type=module -e 'const response=await fetch(`${process.env.HAWK_API_URL}/ai-systems?page=1&page_size=100`,{headers:{Authorization:`Bearer ${process.env.HAWK_ACCESS_TOKEN}`,"X-Tenant-ID":process.env.HAWK_TENANT_ID}}); if(!response.ok) process.exit(1); const body=await response.json(); console.table(body.items.map(({id,name,status,metadata_json:m={}})=>({id,name,status,governance_state:m.governance_state,lifecycle_state:m.lifecycle_state,ownership_state:m.ownership_state})));'
export HAWK_AI_SYSTEM_ID="13a2e2e7-7ae6-454b-8bae-ab1d1946ea99"
```

An active status alone is not sufficient. Hawk correctly rejects authorization
before event creation when governance is not approved, lifecycle is prohibited,
or `ownership_state` is `UNKNOWN` or `MISSING`. The current local BFSI demo
system shown above satisfies those prerequisites. If a selected governed system
is merely inactive, activate it through Hawk's supported API instead of changing
the database:

```zsh
node --input-type=module -e 'const response=await fetch(`${process.env.HAWK_API_URL}/ai-systems/${process.env.HAWK_AI_SYSTEM_ID}`,{method:"PATCH",headers:{Authorization:`Bearer ${process.env.HAWK_ACCESS_TOKEN}`,"X-Tenant-ID":process.env.HAWK_TENANT_ID,"Content-Type":"application/json"},body:JSON.stringify({status:"active"})}); if(!response.ok){console.error(await response.text());process.exit(1)} const body=await response.json(); console.log({id:body.id,status:body.status});'
```

## 3. Record the unknown fingerprint

Run the real proxy and child once:

```zsh
npm --prefix packages/hawk-mcp-proxy run manual:mcp
```

The first run should stop before prompting for a tool call and report:

```text
Outcome: SETUP FAILED
Marker file: absent
Child received tools/call: no
```

Exit code `3` is expected. The live scan has now recorded the exact tool
fingerprint as unknown.

## 4. Bootstrap only the exact local demo fingerprint

> **LOCAL DEMO FIXTURE — NOT A PRODUCTION APPROVAL**

This setup operation is restricted to an existing SQLite file under
`/private/tmp`, the exact `manual-terminal-lab/write_demo_marker@1.0.0`
fingerprint, and an existing tenant owner.

```zsh
apps/api/.venv/bin/python apps/api/scripts/bootstrap_manual_mcp_demo_fingerprint.py \
  --database-url "sqlite+pysqlite:////private/tmp/hawk_mac_demo_20260803T065900Z.db" \
  --tenant-id "$HAWK_TENANT_ID" \
  --owner-email "owner@acme.ai"
```

Expected output includes the fixture warning, one fingerprint ID, the tenant ID,
and `Idempotent: false` on the first successful bootstrap.

## 5. Perform the MCP action yourself

Run the lab again:

```zsh
npm --prefix packages/hawk-mcp-proxy run manual:mcp
```

At this prompt:

```text
Type CALL and press Enter to invoke write_demo_marker through Hawk:
```

type exactly `CALL` and press Enter. Expected proof:

```text
Outcome: BLOCK PROVEN
Marker file: absent
Child received tools/call: no
Enforcement event: a Hawk event UUID
Runtime event: a Hawk runtime event identifier
Correlation ID: a Hawk correlation identifier
```

A generic proxy error without both matching Hawk evidence records is reported as
`NOT PROVEN`, never as a successful policy block.

## 6. Verify the same evidence in the UI

- Command Center: [http://localhost:3001/dashboard/command-center](http://localhost:3001/dashboard/command-center)
- Runtime activity: [http://localhost:3001/runtime-intelligence/activity-map](http://localhost:3001/runtime-intelligence/activity-map)

Use the printed correlation and event identifiers to locate the record and open
its linked action trace.

## 7. Clean up the exact lab directory

Each run prints a complete assignment beginning with:

```text
HAWK_MCP_LAB_DIR=/private/tmp/hawk-mcp-terminal-lab-
```

Copy the complete value from the run, then execute:

```zsh
export HAWK_MCP_LAB_DIR="/private/tmp/hawk-mcp-terminal-lab-COPY_THE_PRINTED_SUFFIX"
npm --prefix packages/hawk-mcp-proxy run manual:mcp:cleanup -- --lab-dir "$HAWK_MCP_LAB_DIR"
```

The cleanup command rejects any path outside Hawk's exact lab prefix.

## Honest limitations

- The fingerprint bootstrap is local fixture scaffolding, not a production MCP
  approval workflow.
- This scenario proves an invalid-authority routed deny only. There is no live allow claim.
- This lab does not claim Claude Desktop or Cursor routing coverage.
- Only MCP calls actually routed through `hawk-mcp-proxy` are inline-controlled.
- A transport failure, scan failure, missing evidence record, or malformed
  response is `SETUP FAILED` or `NOT PROVEN`, never an inflated coverage claim.
