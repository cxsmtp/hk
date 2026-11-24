using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Hawk.AI.MicrosoftAgentFramework.Tests;

public sealed class HawkBankingClientTests
{
    [Fact]
    public async Task AuthorizeAsync_SendsExactMaterialWithoutPersistingToken()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK, TestPayloads.AllowedResponse);
        var tokens = new StaticAccessTokenProvider("memory-only-token");
        var client = new HawkBankingClient(
            new HttpClient(handler) { BaseAddress = new Uri("https://hawk.invalid") },
            tokens,
            "tenant-001");

        BankingAuthorization response = await client.AuthorizeAsync(
            TestPayloads.OwnAccountRequest,
            CancellationToken.None);

        Assert.Equal("allow", response.Decision);
        Assert.Equal("Bearer", handler.Authorization?.Scheme);
        Assert.Equal("memory-only-token", handler.Authorization?.Parameter);
        Assert.Equal("tenant-001", handler.TenantId);
        Assert.Equal("/runtime-control/banking-actions/authorize", handler.RequestUri?.AbsolutePath);
        Assert.NotNull(handler.RequestBody);
        using JsonDocument request = JsonDocument.Parse(handler.RequestBody);
        Assert.Equal(
            TestPayloads.OwnAccountRequest.SubjectAssertion,
            request.RootElement.GetProperty("subject_assertion").GetString());
        Assert.Equal(
            TestPayloads.OwnAccountRequest.RequestedAccountId,
            request.RootElement.GetProperty("requested_account_id").GetString());
        Assert.DoesNotContain("memory-only-token", JsonSerializer.Serialize(response));
        Assert.Equal(1, tokens.CallCount);
    }

    [Fact]
    public async Task ValidateAndReport_UseFreshTokensAndSnakeCaseContracts()
    {
        var handler = new SequencedRecordingHandler(
            (HttpStatusCode.OK, TestPayloads.PreExecutionResponse),
            (HttpStatusCode.OK, TestPayloads.ExecutionResponse));
        var tokens = new SequencedAccessTokenProvider("token-one", "token-two");
        var client = new HawkBankingClient(
            new HttpClient(handler) { BaseAddress = new Uri("https://hawk.invalid") },
            tokens,
            "tenant-001");

        PreExecutionResult gate = await client.ValidatePreExecutionAsync(
            "decision-receipt-001",
            "attempt-001",
            TestPayloads.OwnAccountRequest,
            CancellationToken.None);
        ExecutionResult receipt = await client.ReportExecutionAsync(
            "decision-receipt-001",
            "execution-grant-001",
            "attempt-001",
            "success",
            CancellationToken.None);

        Assert.True(gate.Executable);
        Assert.Equal("matched", receipt.Integrity);
        Assert.Equal(new[] { "token-one", "token-two" }, handler.BearerTokens);
        Assert.Equal(2, tokens.CallCount);
        Assert.Collection(
            handler.RequestBodies,
            first =>
            {
                Assert.Contains("\"execution_attempt_id\":\"attempt-001\"", first);
                Assert.Contains("\"final_action\":", first);
            },
            second =>
            {
                Assert.Contains("\"execution_grant_id\":\"execution-grant-001\"", second);
                Assert.Contains("\"execution_attempt_id\":\"attempt-001\"", second);
            });
    }

    [Fact]
    public async Task NonSuccessResponse_DoesNotExposeTokenOrServerBody()
    {
        var handler = new RecordingHandler(
            HttpStatusCode.UnprocessableEntity,
            "{\"detail\":\"secret-subject-assertion\"}");
        var client = new HawkBankingClient(
            new HttpClient(handler) { BaseAddress = new Uri("https://hawk.invalid") },
            new StaticAccessTokenProvider("memory-only-token"),
            "tenant-001");

        HttpRequestException error = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.AuthorizeAsync(TestPayloads.OwnAccountRequest, CancellationToken.None));

        Assert.DoesNotContain("memory-only-token", error.ToString());
        Assert.DoesNotContain("secret-subject-assertion", error.ToString());
    }

    [Fact]
    public async Task MalformedSuccessfulExecutionResponse_IsRejected()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK, "{}");
        var client = new HawkBankingClient(
            new HttpClient(handler) { BaseAddress = new Uri("https://hawk.invalid") },
            new StaticAccessTokenProvider("memory-only-token"),
            "tenant-001");

        await Assert.ThrowsAsync<InvalidDataException>(() => client.ReportExecutionAsync(
            "decision-receipt-001",
            "execution-grant-001",
            "attempt-001",
            "success",
            CancellationToken.None));
    }

    [Fact]
    public void BankingActionRequest_FreezesInputsAndRedactsStringFormatting()
    {
        var delegated = new List<string> { "agent-one" };
        var arguments = new Dictionary<string, object?>
        {
            ["account_id"] = "acct-001",
            ["nested"] = new Dictionary<string, object?> { ["value"] = "original" },
        };
        BankingActionRequest request = TestPayloads.CreateRequest(arguments, delegated);

        delegated.Add("agent-two");
        arguments["account_id"] = "acct-999";
        ((Dictionary<string, object?>)arguments["nested"]!)["value"] = "mutated";

        string serialized = JsonSerializer.Serialize(request);
        Assert.Contains("acct-001", serialized);
        Assert.Contains("original", serialized);
        Assert.DoesNotContain("acct-999", serialized);
        Assert.DoesNotContain("mutated", serialized);
        Assert.DoesNotContain("agent-two", serialized);
        Assert.DoesNotContain(request.SubjectAssertion, request.ToString());
        Assert.DoesNotContain(request.RequestedAccountId, request.ToString());
    }
}

internal static class TestPayloads
{
    internal static readonly BankingActionRequest OwnAccountRequest = new(
        SubjectAssertion: "synthetic-signed-bank-assertion-that-is-long-enough",
        AiTransactionId: "transaction-001",
        ActionId: "action-001",
        ChainId: "chain-001",
        AiSystemId: "foundry-bank-agent",
        SourceAgentId: "bank-summary-agent",
        DelegatedAgentIds: Array.Empty<string>(),
        ActionType: "tool_execution",
        OperationType: "read_summary",
        ToolName: "get_account_summary",
        ToolVersion: "1.0.0",
        ToolSchemaFingerprint: new string('a', 64),
        Arguments: new Dictionary<string, object?>
        {
            ["account_id"] = "acct-001",
            ["view"] = "summary",
        },
        RequestedCustomerSubjectId: "customer-001",
        RequestedAccountId: "acct-001",
        RequestedResource: "bank.customer/current/summary",
        Destination: "bank-core.internal",
        WorkloadIdentity: "foundry-managed-identity",
        WorkloadIdentityType: "project_managed_identity",
        WorkloadAuthenticationMode: "managed_identity",
        WorkloadIdentitySource: "microsoft_entra",
        WorkloadIdentityProvenance: "verified_entra_claims",
        SideEffectClass: "read_only",
        PolicySnapshotId: "bank-policy-v1");

    internal static BankingActionRequest CreateRequest(
        IReadOnlyDictionary<string, object?> arguments,
        IReadOnlyList<string> delegatedAgentIds) => new(
            SubjectAssertion: "synthetic-signed-bank-assertion-that-is-long-enough",
            AiTransactionId: "transaction-001",
            ActionId: "action-001",
            ChainId: "chain-001",
            AiSystemId: "foundry-bank-agent",
            SourceAgentId: "bank-summary-agent",
            DelegatedAgentIds: delegatedAgentIds,
            ActionType: "tool_execution",
            OperationType: "read_summary",
            ToolName: "get_account_summary",
            ToolVersion: "1.0.0",
            ToolSchemaFingerprint: new string('a', 64),
            Arguments: arguments,
            RequestedCustomerSubjectId: "customer-001",
            RequestedAccountId: "acct-001",
            RequestedResource: "bank.customer/current/summary",
            Destination: "bank-core.internal",
            WorkloadIdentity: "foundry-managed-identity",
            WorkloadIdentityType: "project_managed_identity",
            WorkloadAuthenticationMode: "managed_identity",
            WorkloadIdentitySource: "microsoft_entra",
            WorkloadIdentityProvenance: "verified_entra_claims",
            SideEffectClass: "read_only",
            PolicySnapshotId: "bank-policy-v1");

    internal static BankingActionRequest WithAccount(
        BankingActionRequest source,
        string accountId) => new(
            source.SubjectAssertion,
            source.AiTransactionId,
            source.ActionId,
            source.ChainId,
            source.AiSystemId,
            source.SourceAgentId,
            source.DelegatedAgentIds,
            source.ActionType,
            source.OperationType,
            source.ToolName,
            source.ToolVersion,
            source.ToolSchemaFingerprint,
            new Dictionary<string, object?>
            {
                ["account_id"] = accountId,
                ["view"] = "summary",
            },
            source.RequestedCustomerSubjectId,
            accountId,
            source.RequestedResource,
            source.Destination,
            source.WorkloadIdentity,
            source.WorkloadIdentityType,
            source.WorkloadAuthenticationMode,
            source.WorkloadIdentitySource,
            source.WorkloadIdentityProvenance,
            source.SideEffectClass,
            source.PolicySnapshotId,
            source.TransportBinding);

    internal const string AllowedResponse = """
        {
          "ai_transaction_id": "transaction-001",
          "action_id": "action-001",
          "chain_id": "chain-001",
          "decision": "allow",
          "reason_code": "bank_policy_allowed",
          "control_mode": "inline_allowed",
          "decision_receipt_id": "decision-receipt-001",
          "canonical_action": {
            "schema_version": "1.0",
            "action": { "tool_name": "get_account_summary" }
          },
          "subject": {
            "tenant_id": "tenant-001",
            "ai_transaction_id": "transaction-001"
          }
        }
        """;

    internal const string PreExecutionResponse = """
        {
          "executable":true,
          "integrity_result_id":null,
          "execution_grant_id":"execution-grant-001",
          "grant_expires_at":"2026-08-14T10:00:30Z"
        }
        """;

    internal const string ExecutionResponse = """
        {
          "execution_receipt_id":"execution-receipt-001",
          "integrity_result_id":"integrity-result-001",
          "integrity":"matched",
          "drift_fields":[]
        }
        """;

    internal static JsonElement CanonicalAction =>
        JsonDocument.Parse("{\"schema_version\":\"1.0\",\"action\":{\"tool_name\":\"get_account_summary\"}}")
            .RootElement
            .Clone();
}

internal sealed class StaticAccessTokenProvider(string token) : IHawkAccessTokenProvider
{
    internal int CallCount { get; private set; }

    public ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CallCount++;
        return ValueTask.FromResult(token);
    }
}

internal sealed class SequencedAccessTokenProvider(params string[] tokens) : IHawkAccessTokenProvider
{
    private int _index;

    internal int CallCount => _index;

    public ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_index >= tokens.Length)
        {
            throw new InvalidOperationException("No test access token remains.");
        }

        return ValueTask.FromResult(tokens[_index++]);
    }
}

internal class RecordingHandler(HttpStatusCode statusCode, string responseBody) : HttpMessageHandler
{
    internal AuthenticationHeaderValue? Authorization { get; private set; }
    internal string? TenantId { get; private set; }
    internal Uri? RequestUri { get; private set; }
    internal string? RequestBody { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Authorization = request.Headers.Authorization;
        TenantId = request.Headers.TryGetValues("X-Tenant-ID", out IEnumerable<string>? values)
            ? values.Single()
            : null;
        RequestUri = request.RequestUri;
        RequestBody = request.Content is null
            ? null
            : await request.Content.ReadAsStringAsync(cancellationToken);
        return JsonResponse(statusCode, responseBody);
    }

    internal static HttpResponseMessage JsonResponse(HttpStatusCode status, string body) => new(status)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    };
}

internal sealed class SequencedRecordingHandler(
    params (HttpStatusCode Status, string Body)[] responses) : HttpMessageHandler
{
    private int _index;

    internal List<string> BearerTokens { get; } = [];
    internal List<string> RequestBodies { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        BearerTokens.Add(request.Headers.Authorization?.Parameter ?? string.Empty);
        RequestBodies.Add(
            request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken));
        (HttpStatusCode status, string body) = responses[_index++];
        return RecordingHandler.JsonResponse(status, body);
    }
}
