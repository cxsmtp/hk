using System.Text.Json;
using Xunit;

namespace Hawk.AI.MicrosoftAgentFramework.Tests;

public sealed class HawkTransportAdaptersTests
{
    [Fact]
    public void Bindings_CoverFunctionMcpToolboxRestOpenApiAndApimExactly()
    {
        HawkTransportBinding[] bindings =
        [
            HawkTransportBindings.Function(
                "route:function",
                "managed_identity",
                "function:get_account_summary:1.0.0"),
            HawkTransportBindings.Mcp(
                "route:mcp",
                "oauth_passthrough",
                "mcp-bank-core",
                "get_account_summary",
                "1.0.0",
                "tool-fingerprint-001"),
            HawkTransportBindings.Toolbox(
                "route:toolbox",
                "project_managed_identity",
                "foundry-bank-toolbox",
                "7",
                "foundry-bank-connection",
                "mcp-bank-core",
                "get_account_summary",
                "1.0.0",
                "tool-fingerprint-001"),
            HawkTransportBindings.Rest(
                "route:rest",
                "managed_identity",
                "POST",
                "/customers/{customer}/accounts/{account}/summary"),
            HawkTransportBindings.OpenApi(
                "route:openapi",
                "managed_identity",
                "POST",
                "/customers/{customer}/accounts/{account}/summary",
                "getAccountSummary",
                new string('d', 64)),
            HawkTransportBindings.Apim(
                "route:apim",
                "managed_identity",
                "POST",
                "/customers/{customer}/accounts/{account}/summary",
                "getAccountSummary",
                new string('d', 64),
                "banking-api",
                "3",
                "bank-core-backend"),
        ];

        Assert.Equal(
            new[] { "function", "mcp", "toolbox", "rest", "openapi", "apim" },
            bindings.Select(binding => binding.Transport));
        Assert.Equal(6, bindings.Select(binding => binding.RouteId).Distinct().Count());
        Assert.DoesNotContain(bindings, binding => binding.DirectBypass);
        Assert.Equal("tool-fingerprint-001", bindings[1].McpToolFingerprintId);
        Assert.Equal("foundry-bank-connection", bindings[2].ProjectConnectionId);
        Assert.Equal("bank-core-backend", bindings[5].ApimBackendId);
    }

    [Fact]
    public void Bind_ProducesTheExistingRequestWithSnakeCaseTransportMaterial()
    {
        HawkTransportBinding binding = HawkTransportBindings.Mcp(
            "route:mcp",
            "managed_identity",
            "mcp-bank-core",
            "get_account_summary",
            "1.0.0",
            "tool-fingerprint-001");

        BankingActionRequest bound = HawkBankingTransportAdapters.Bind(
            TestPayloads.OwnAccountRequest,
            binding);
        string serialized = JsonSerializer.Serialize(
            bound,
            new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            });

        Assert.Same(binding, bound.TransportBinding);
        Assert.Equal(TestPayloads.OwnAccountRequest.Arguments, bound.Arguments);
        Assert.Contains("\"transport_binding\"", serialized);
        Assert.Contains("\"mcp_tool_fingerprint_id\":\"tool-fingerprint-001\"", serialized);
        Assert.DoesNotContain("subject_assertion\":null", serialized);
    }

    [Fact]
    public void InvalidOrIncompleteBinding_FailsBeforeProviderExecution()
    {
        Assert.Throws<ArgumentException>(() => new HawkTransportBinding(
            Transport: "mcp",
            RouteId: "route:mcp",
            AuthenticationMode: "managed_identity"));
        Assert.Throws<ArgumentException>(() => HawkTransportBindings.OpenApi(
            "route:openapi",
            "managed_identity",
            "POST",
            "/summary",
            "getSummary",
            "not-a-sha256"));
    }

    [Fact]
    public async Task RouteMutation_IsDeniedByFinalGateBeforeNext()
    {
        var authorization = new BankingAuthorization(
            "transaction-001",
            "action-001",
            "chain-001",
            "allow",
            "bank_policy_allowed",
            "inline_allowed",
            "decision-receipt-001",
            TestPayloads.CanonicalAction);
        var hawk = new StubHawkClient(authorization);
        var gate = new HawkFunctionExecutionGate(hawk);
        var invocations = 0;
        BankingActionRequest preliminary = HawkBankingTransportAdapters.Bind(
            TestPayloads.OwnAccountRequest,
            HawkTransportBindings.Function(
                "route:function:approved",
                "managed_identity",
                "function:get_account_summary:1.0.0"));
        BankingActionRequest mutated = HawkBankingTransportAdapters.Bind(
            TestPayloads.OwnAccountRequest,
            HawkTransportBindings.Function(
                "route:function:bypass",
                "managed_identity",
                "function:get_account_summary:1.0.0"));

        HawkFunctionResult result = await gate.ExecuteAsync(
            preliminary,
            () => mutated,
            _ =>
            {
                invocations++;
                return ValueTask.FromResult<object?>(null);
            },
            CancellationToken.None);

        Assert.False(result.Executed);
        Assert.Equal(0, invocations);
        Assert.Equal("drift_result", result.Decision);
        Assert.Equal(new[] { "authorize", "pre_execution" }, hawk.Calls);
    }
}
