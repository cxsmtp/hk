using System.Text.Json;
using Hawk.AI.MicrosoftAgentFramework;

return await HawkBankFoundryReference.RunAsync();

internal static class HawkBankFoundryReference
{
    internal static async Task<int> RunAsync()
    {
        Uri apiUrl = RequireAbsoluteUri("HAWK_API_URL");
        string tenantId = RequireEnvironment("HAWK_TENANT_ID");
        string subjectAssertion = RequireEnvironment("HAWK_BANK_SUBJECT_ASSERTION");
        string transactionId = Environment.GetEnvironmentVariable("HAWK_AI_TRANSACTION_ID")
            ?? $"bank-reference-{Guid.NewGuid():N}";
        string customerId = Environment.GetEnvironmentVariable("HAWK_CUSTOMER_SUBJECT_ID")
            ?? "customer-001";
        string ownAccountId = Environment.GetEnvironmentVariable("HAWK_OWN_ACCOUNT_ID")
            ?? "acct-001";
        string crossCustomerAccountId = Environment.GetEnvironmentVariable("HAWK_CROSS_ACCOUNT_ID")
            ?? "acct-999";

        using var httpClient = new HttpClient { BaseAddress = apiUrl };
        var hawk = new HawkBankingClient(
            httpClient,
            new EnvironmentAccessTokenProvider("HAWK_ACCESS_TOKEN"),
            tenantId);
        var gate = new HawkFunctionExecutionGate(hawk);
        var bank = new InMemoryBank(
            new Dictionary<string, AccountSummary>(StringComparer.Ordinal)
            {
                [ownAccountId] = new(42.00m, "AED"),
                [crossCustomerAccountId] = new(999.00m, "AED"),
            },
            crossCustomerAccountId);

        BankingActionRequest ownRequest = CreateRequest(
            subjectAssertion,
            transactionId,
            actionId: "own-account-summary",
            customerId,
            ownAccountId);
        BankingActionRequest crossCustomerRequest = CreateRequest(
            subjectAssertion,
            transactionId,
            actionId: "cross-customer-summary",
            customerId,
            crossCustomerAccountId);

        HawkFunctionResult own = await gate.ExecuteAsync(
            ownRequest,
            () => ownRequest,
            _ => ValueTask.FromResult<object?>(bank.ReadSummary(ownAccountId)),
            CancellationToken.None);
        HawkFunctionResult crossCustomer = await gate.ExecuteAsync(
            crossCustomerRequest,
            () => crossCustomerRequest,
            _ => ValueTask.FromResult<object?>(bank.ReadSummary(crossCustomerAccountId)),
            CancellationToken.None);

        var proof = new
        {
            own_account = new
            {
                own.Decision,
                own.Executed,
                own.EvidenceComplete,
                own.Integrity,
                own.DecisionReceiptId,
                own.ExecutionReceiptId,
                own.IntegrityResultId,
            },
            cross_customer = new
            {
                crossCustomer.Decision,
                crossCustomer.Executed,
                crossCustomer.EvidenceComplete,
                crossCustomer.DecisionReceiptId,
            },
            bank.CrossCustomerReadCount,
        };
        Console.WriteLine(JsonSerializer.Serialize(proof, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            WriteIndented = true,
        }));

        bool passed = own.Decision == "allow"
            && own.Executed
            && own.EvidenceComplete
            && own.Integrity == "matched"
            && crossCustomer.Decision == "block"
            && !crossCustomer.Executed
            && bank.CrossCustomerReadCount == 0;
        return passed ? 0 : 2;
    }

    private static BankingActionRequest CreateRequest(
        string subjectAssertion,
        string transactionId,
        string actionId,
        string customerId,
        string accountId)
    {
        return new BankingActionRequest(
            subjectAssertion,
            transactionId,
            actionId,
            ChainId: $"chain:{transactionId}",
            AiSystemId: Environment.GetEnvironmentVariable("HAWK_AI_SYSTEM_ID")
                ?? "foundry-bank-agent",
            SourceAgentId: Environment.GetEnvironmentVariable("HAWK_SOURCE_AGENT_ID")
                ?? "bank-summary-agent",
            DelegatedAgentIds: Array.Empty<string>(),
            ActionType: "tool_execution",
            OperationType: "read_summary",
            ToolName: Environment.GetEnvironmentVariable("HAWK_TOOL_NAME")
                ?? "get_account_summary",
            ToolVersion: Environment.GetEnvironmentVariable("HAWK_TOOL_VERSION")
                ?? "1.0.0",
            ToolSchemaFingerprint: Environment.GetEnvironmentVariable(
                    "HAWK_TOOL_SCHEMA_FINGERPRINT")
                ?? new string('a', 64),
            Arguments: new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["account_id"] = accountId,
                ["view"] = "summary",
            },
            RequestedCustomerSubjectId: customerId,
            RequestedAccountId: accountId,
            RequestedResource: Environment.GetEnvironmentVariable("HAWK_REQUESTED_RESOURCE")
                ?? "bank.customer/current/summary",
            Destination: Environment.GetEnvironmentVariable("HAWK_DESTINATION")
                ?? "bank-core.internal",
            WorkloadIdentity: Environment.GetEnvironmentVariable("HAWK_WORKLOAD_IDENTITY")
                ?? "foundry-managed-identity",
            WorkloadIdentityType: "project_managed_identity",
            WorkloadAuthenticationMode: "managed_identity",
            WorkloadIdentitySource: "microsoft_entra",
            WorkloadIdentityProvenance: "verified_entra_claims",
            SideEffectClass: "read_only",
            PolicySnapshotId: Environment.GetEnvironmentVariable("HAWK_POLICY_SNAPSHOT_ID")
                ?? "bank-policy-v1");
    }

    private static Uri RequireAbsoluteUri(string name)
    {
        string value = RequireEnvironment(name);
        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? result))
        {
            throw new InvalidOperationException($"{name} must be an absolute URI.");
        }

        return result;
    }

    private static string RequireEnvironment(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrWhiteSpace(value)
            ? throw new InvalidOperationException($"Required environment variable {name} is missing.")
            : value;
    }
}

internal sealed class EnvironmentAccessTokenProvider(string variableName)
    : IHawkAccessTokenProvider
{
    public ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string? token = Environment.GetEnvironmentVariable(variableName);
        return string.IsNullOrWhiteSpace(token)
            ? throw new InvalidOperationException(
                "The process-scoped Hawk access token is unavailable.")
            : ValueTask.FromResult(token);
    }
}

internal sealed record AccountSummary(decimal Balance, string Currency);

internal sealed class InMemoryBank(
    IReadOnlyDictionary<string, AccountSummary> accounts,
    string crossCustomerAccountId)
{
    internal int CrossCustomerReadCount { get; private set; }

    internal AccountSummary ReadSummary(string accountId)
    {
        if (accountId == crossCustomerAccountId)
        {
            CrossCustomerReadCount++;
        }

        return accounts.TryGetValue(accountId, out AccountSummary? summary)
            ? summary
            : throw new KeyNotFoundException("The synthetic reference account was not found.");
    }
}
