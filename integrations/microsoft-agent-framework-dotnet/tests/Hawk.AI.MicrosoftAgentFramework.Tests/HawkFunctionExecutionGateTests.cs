using System.Text.Json;
using Xunit;

namespace Hawk.AI.MicrosoftAgentFramework.Tests;

public sealed class HawkFunctionExecutionGateTests
{
    [Fact]
    public async Task ExecuteAsync_Block_DoesNotInvokeNext()
    {
        var hawk = new StubHawkClient(BlockedAuthorization());
        var gate = new HawkFunctionExecutionGate(hawk);
        var invocations = 0;

        HawkFunctionResult result = await gate.ExecuteAsync(
            TestPayloads.OwnAccountRequest,
            finalMaterial: () => TestPayloads.OwnAccountRequest,
            next: _ =>
            {
                invocations++;
                return ValueTask.FromResult<object?>(new { balance = 42 });
            },
            cancellationToken: CancellationToken.None);

        Assert.False(result.Executed);
        Assert.Equal(0, invocations);
        Assert.Equal("block", result.Decision);
        Assert.NotNull(result.Denial);
        Assert.Equal(new[] { "authorize" }, hawk.Calls);
    }

    [Fact]
    public async Task ExecuteAsync_Allow_ValidatesThenInvokesExactlyOnceAndReportsMatchedExecution()
    {
        var hawk = new StubHawkClient(AllowedAuthorization());
        var gate = new HawkFunctionExecutionGate(hawk);
        var invocations = 0;

        HawkFunctionResult result = await gate.ExecuteAsync(
            TestPayloads.OwnAccountRequest,
            finalMaterial: () => TestPayloads.OwnAccountRequest,
            next: _ =>
            {
                invocations++;
                hawk.Calls.Add("execute");
                return ValueTask.FromResult<object?>(new { balance = 42 });
            },
            cancellationToken: CancellationToken.None);

        Assert.True(result.Executed);
        Assert.True(result.EvidenceComplete);
        Assert.Equal(1, invocations);
        Assert.Equal("matched", result.Integrity);
        Assert.Equal(
            new[] { "authorize", "pre_execution", "execute", "report_execution" },
            hawk.Calls);
    }

    [Fact]
    public async Task ExecuteAsync_MutatedFinalMaterial_IsDeniedBeforeNextAndSentForDriftEvidence()
    {
        var hawk = new StubHawkClient(AllowedAuthorization())
        {
            PreExecution = new PreExecutionResult(
                false,
                "drift-result-001",
                null,
                null),
        };
        var gate = new HawkFunctionExecutionGate(hawk);
        var invocations = 0;
        BankingActionRequest mutated = TestPayloads.WithAccount(
            TestPayloads.OwnAccountRequest,
            "acct-mutated");

        HawkFunctionResult result = await gate.ExecuteAsync(
            TestPayloads.OwnAccountRequest,
            finalMaterial: () => mutated,
            next: _ =>
            {
                invocations++;
                return ValueTask.FromResult<object?>(null);
            },
            cancellationToken: CancellationToken.None);

        Assert.False(result.Executed);
        Assert.Equal(0, invocations);
        Assert.Equal("drift_result", result.Decision);
        Assert.Equal("drift-result-001", result.IntegrityResultId);
        Assert.Equal(new[] { "authorize", "pre_execution" }, hawk.Calls);
        BankingActionRequest actual = Assert.Single(hawk.ValidatedRequests);
        Assert.Equal("acct-mutated", actual.RequestedAccountId);
    }

    [Fact]
    public async Task ExecuteAsync_RequireApprovalWithoutBoundApproval_DoesNotInvokeNext()
    {
        var hawk = new StubHawkClient(AllowedAuthorization() with
        {
            Decision = "require_approval",
            ReasonCode = "approval_required",
            ControlMode = "inline_approval_required",
        });
        var gate = new HawkFunctionExecutionGate(hawk);
        var invocations = 0;

        HawkFunctionResult result = await gate.ExecuteAsync(
            TestPayloads.OwnAccountRequest,
            () => TestPayloads.OwnAccountRequest,
            _ =>
            {
                invocations++;
                return ValueTask.FromResult<object?>(null);
            },
            CancellationToken.None);

        Assert.False(result.Executed);
        Assert.Equal(0, invocations);
        Assert.Equal("require_approval", result.Decision);
        Assert.Equal(new[] { "authorize" }, hawk.Calls);
    }

    [Fact]
    public async Task ExecuteAsync_ReportFailureAfterExecution_RemainsExecutedAndEvidenceIncomplete()
    {
        var hawk = new StubHawkClient(AllowedAuthorization())
        {
            ReportException = new HttpRequestException("receipt transport unavailable"),
        };
        var gate = new HawkFunctionExecutionGate(hawk);
        var invocations = 0;

        HawkFunctionResult result = await gate.ExecuteAsync(
            TestPayloads.OwnAccountRequest,
            () => TestPayloads.OwnAccountRequest,
            _ =>
            {
                invocations++;
                hawk.Calls.Add("execute");
                return ValueTask.FromResult<object?>(new { balance = 42 });
            },
            CancellationToken.None);

        Assert.True(result.Executed);
        Assert.False(result.EvidenceComplete);
        Assert.Equal(1, invocations);
        Assert.Equal("evidence_unavailable", result.Integrity);
        Assert.Equal(
            new[] { "authorize", "pre_execution", "execute", "report_execution" },
            hawk.Calls);
    }

    [Fact]
    public async Task ExecuteAsync_AuthorizationTransportFailure_DoesNotInvokeNext()
    {
        var hawk = new StubHawkClient(AllowedAuthorization())
        {
            AuthorizeException = new HttpRequestException("Hawk unavailable"),
        };
        var gate = new HawkFunctionExecutionGate(hawk);
        var invocations = 0;

        await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await gate.ExecuteAsync(
                TestPayloads.OwnAccountRequest,
                () => TestPayloads.OwnAccountRequest,
                _ =>
                {
                    invocations++;
                    return ValueTask.FromResult<object?>(null);
                },
                CancellationToken.None));

        Assert.Equal(0, invocations);
        Assert.Equal(new[] { "authorize" }, hawk.Calls);
    }

    [Fact]
    public async Task ExecuteAsync_FunctionFailure_ReportsFailureWithSameGrantAndRethrows()
    {
        var hawk = new StubHawkClient(AllowedAuthorization());
        var gate = new HawkFunctionExecutionGate(hawk);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await gate.ExecuteAsync(
                TestPayloads.OwnAccountRequest,
                () => TestPayloads.OwnAccountRequest,
                _ => throw new InvalidOperationException("synthetic tool failure"),
                CancellationToken.None));

        Assert.Equal(new[] { "authorize", "pre_execution", "report_execution" }, hawk.Calls);
        Assert.Equal(new[] { "failure" }, hawk.ReportedExecutionStatuses);
        Assert.Equal(new[] { "execution-grant-001" }, hawk.ReportedGrantIds);
    }

    private static BankingAuthorization AllowedAuthorization() => new(
        AiTransactionId: "transaction-001",
        ActionId: "action-001",
        ChainId: "chain-001",
        Decision: "allow",
        ReasonCode: "bank_policy_allowed",
        ControlMode: "inline_allowed",
        DecisionReceiptId: "decision-receipt-001",
        CanonicalAction: TestPayloads.CanonicalAction);

    private static BankingAuthorization BlockedAuthorization() => AllowedAuthorization() with
    {
        Decision = "block",
        ReasonCode = "bank_customer_scope_mismatch",
        ControlMode = "inline_prevented",
    };
}

internal sealed class StubHawkClient(BankingAuthorization authorization)
    : IHawkBankingControlClient
{
    internal List<string> Calls { get; } = [];
    internal List<BankingActionRequest> ValidatedRequests { get; } = [];
    internal List<string> ReportedExecutionStatuses { get; } = [];
    internal List<string> ReportedGrantIds { get; } = [];
    internal Exception? AuthorizeException { get; init; }
    internal Exception? ReportException { get; init; }
    internal PreExecutionResult PreExecution { get; init; } = new(
        true,
        null,
        "execution-grant-001",
        DateTimeOffset.UtcNow.AddSeconds(30));

    public Task<BankingAuthorization> AuthorizeAsync(
        BankingActionRequest request,
        CancellationToken cancellationToken)
    {
        Calls.Add("authorize");
        if (AuthorizeException is not null)
        {
            return Task.FromException<BankingAuthorization>(AuthorizeException);
        }

        return Task.FromResult(authorization);
    }

    public Task<PreExecutionResult> ValidatePreExecutionAsync(
        string decisionReceiptId,
        string executionAttemptId,
        BankingActionRequest finalAction,
        CancellationToken cancellationToken)
    {
        Calls.Add("pre_execution");
        ValidatedRequests.Add(finalAction);
        return Task.FromResult(PreExecution);
    }

    public Task<ExecutionResult> ReportExecutionAsync(
        string decisionReceiptId,
        string executionGrantId,
        string executionAttemptId,
        string executionStatus,
        CancellationToken cancellationToken)
    {
        Calls.Add("report_execution");
        ReportedExecutionStatuses.Add(executionStatus);
        ReportedGrantIds.Add(executionGrantId);
        if (ReportException is not null)
        {
            return Task.FromException<ExecutionResult>(ReportException);
        }

        return Task.FromResult(
            new ExecutionResult(
                "execution-receipt-001",
                "integrity-result-001",
                "matched",
                Array.Empty<string>()));
    }
}
