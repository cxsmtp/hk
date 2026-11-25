# Hawk Microsoft Agent Framework — Banking Function Proof

This package is Hawk's first path-native .NET proof for an exact banking function boundary. It uses the existing Hawk authorization kernel and Decision/Execution Receipts; it does not contain a second policy engine.

## Proved boundary

```text
bank-issued subject assertion
  → Microsoft Agent Framework function callback
  → Hawk authorize
  → final material deep-frozen and re-read
  → Hawk pre-execution validation + one-time execution grant
  → protected function with the sealed argument snapshot, at most once
  → Hawk execution receipt consuming the same grant
```

An own-account summary can execute only after Hawk returns an executable decision, the final material matches, and a short-lived grant is issued for that exact attempt. A cross-customer request returns `HawkToolDeniedResult`; the protected function delegate is not called. Downstream middleware receives a clone for compatibility, while the protected function executes with Hawk's hidden sealed argument snapshot.

## Versions and locked restore

- .NET SDK `8.0.423`
- `Microsoft.Agents.AI` `1.15.0`
- `Microsoft.NET.Test.Sdk` `18.8.1`
- xUnit `2.9.3`
- xUnit Visual Studio runner `3.1.5`

```bash
cd "/opt/hawk/integrations/microsoft-agent-framework-dotnet"

"$HOME/.dotnet/dotnet" restore Hawk.BankFoundry.sln --locked-mode
"$HOME/.dotnet/dotnet" test Hawk.BankFoundry.sln \
  --no-restore \
  --configuration Release
```

The package locks are checked per project. AppleDouble `._*` metadata is excluded only inside this integration so external-drive metadata cannot enter C# compilation.

## Agent Framework registration

Register the exact final callback on the `AIAgentBuilder` closest to the function executor:

```csharp
HawkAgentFrameworkMiddleware hawkMiddleware = new(
    new HawkFunctionExecutionGate(hawkClient),
    bankingMaterialFactory);

AIAgent governedAgent = baseAgent
    .AsBuilder()
    .Use(hawkMiddleware.InvokeAsync)
    .Build();
```

`IBankingActionMaterialFactory` must read the validated `FunctionInvocationContext.Arguments` and immutable bank-issued subject context. It must never derive customer authority or consequential arguments from prompt prose or model output. No material-changing middleware may run between Hawk's final callback and the actual function executor.

## Live local reference proof

The reference uses a synthetic in-memory bank—never a real account or provider. The Hawk API must have the approved banking feature flag, trust issuer, policy profile and receipt signing configured. The subject assertion must authorize the synthetic own account and use the same transaction for both proof actions.

Enter secrets through hidden prompts so values do not enter shell history:

```bash
cd "/opt/hawk/integrations/microsoft-agent-framework-dotnet"

export HAWK_API_URL="http://127.0.0.1:8000"
export HAWK_TENANT_ID="<tenant-id>"

read -rs "HAWK_ACCESS_TOKEN?Hawk access token: "
echo
export HAWK_ACCESS_TOKEN

read -rs "HAWK_BANK_SUBJECT_ASSERTION?Bank subject assertion: "
echo
export HAWK_BANK_SUBJECT_ASSERTION

"$HOME/.dotnet/dotnet" run \
  --project samples/Hawk.BankFoundry.Reference/Hawk.BankFoundry.Reference.csproj \
  --configuration Release \
  --no-restore

unset HAWK_ACCESS_TOKEN HAWK_BANK_SUBJECT_ASSERTION
```

Success requires all of the following in the JSON output:

- `own_account.decision = allow`
- `own_account.executed = true`
- `own_account.integrity = matched`
- Decision, Execution and integrity-result receipt IDs are present
- `cross_customer.decision = block`
- `cross_customer.executed = false`
- `cross_customer_read_count = 0`

The program exits with code `2` if any proof invariant fails. It never prints the access token, subject assertion, customer ID or account ID.

## Secret boundary

`HawkBankingClient` asks `IHawkAccessTokenProvider` for a token per request and never stores that token in a client field, response, exception body, log or file. Successful responses are contract-validated before the adapter can label evidence complete. The environment provider in the reference host is local acceptance scaffolding only. Bank deployment must replace it with workload identity and the approved tenant KMS/HSM-backed credential transport.

## Not yet claimed

This package proves only the local Function middleware path. The following remain independently unverified:

- real Foundry agent/model and `IChatClient` calls;
- structured-response and streaming assurance;
- trusted approval UX and exact approval binding;
- MCP/Foundry Toolbox;
- APIM, OpenAPI and direct REST parity;
- mutation/order acceptance with third-party middleware;
- A2A delegation;
- Sentinel projection and delivery health;
- Control Coverage promotion;
- tenant production KMS/HSM keys and external Foundry/APIM/Sentinel acceptance.
