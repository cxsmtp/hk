using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Xunit;

namespace Hawk.AI.MicrosoftAgentFramework.Tests;

public sealed class HawkAgentFrameworkMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_BlockedActionReturnsTypedDenialWithoutCallingFrameworkNext()
    {
        var hawk = new StubHawkClient(BlockedAuthorization());
        var material = new StubMaterialFactory(TestPayloads.OwnAccountRequest);
        var middleware = new HawkAgentFrameworkMiddleware(
            new HawkFunctionExecutionGate(hawk),
            material);
        FunctionInvocationContext context = CreateOwnAccountContext();
        var nextInvocations = 0;

        object? result = await middleware.InvokeAsync(
            null!,
            context,
            (_, _) =>
            {
                nextInvocations++;
                return ValueTask.FromResult<object?>(new { balance = 42 });
            },
            CancellationToken.None);

        HawkToolDeniedResult denied = Assert.IsType<HawkToolDeniedResult>(result);
        Assert.Equal("block", denied.Decision);
        Assert.Equal("bank_customer_scope_mismatch", denied.ReasonCode);
        Assert.Equal(0, nextInvocations);
        Assert.Equal(1, material.CallCount);
    }

    [Fact]
    public async Task InvokeAsync_AllowedActionReadsFinalContextThenReturnsFunctionOutput()
    {
        var hawk = new StubHawkClient(AllowedAuthorization());
        var material = new StubMaterialFactory(TestPayloads.OwnAccountRequest);
        var middleware = new HawkAgentFrameworkMiddleware(
            new HawkFunctionExecutionGate(hawk),
            material);
        FunctionInvocationContext context = CreateOwnAccountContext();
        var expected = new { balance = 42 };
        var nextInvocations = 0;

        object? result = await middleware.InvokeAsync(
            null!,
            context,
            (observedContext, _) =>
            {
                Assert.NotSame(context, observedContext);
                nextInvocations++;
                return ValueTask.FromResult<object?>(expected);
            },
            CancellationToken.None);

        Assert.Same(expected, result);
        Assert.Equal(1, nextInvocations);
        Assert.Equal(2, material.CallCount);
    }

    [Fact]
    public async Task InvokeAsync_DownstreamArgumentMutationCannotChangeExecutedFunctionMaterial()
    {
        string? executedAccount = null;
        AIFunction function = AIFunctionFactory.Create(
            (Func<string, object?>)(account_id =>
            {
                executedAccount = account_id;
                return new { account_id, balance = 42 };
            }),
            "get_account_summary",
            "Synthetic account summary");
        var context = new FunctionInvocationContext
        {
            Function = function,
            Arguments = new AIFunctionArguments
            {
                ["account_id"] = "acct-001",
                ["view"] = "summary",
            },
        };
        var hawk = new StubHawkClient(AllowedAuthorization());
        var middleware = new HawkAgentFrameworkMiddleware(
            new HawkFunctionExecutionGate(hawk),
            new ContextAccountMaterialFactory());

        object? result = await middleware.InvokeAsync(
            null!,
            context,
            async (sealedContext, token) =>
            {
                sealedContext.Arguments["account_id"] = "acct-999";
                return await sealedContext.Function.InvokeAsync(
                    sealedContext.Arguments,
                    token);
            },
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal("acct-001", executedAccount);
        Assert.Equal("acct-001", Assert.Single(hawk.ValidatedRequests).RequestedAccountId);
    }

    private static FunctionInvocationContext CreateOwnAccountContext() => new()
    {
        Arguments = new AIFunctionArguments
        {
            ["account_id"] = "acct-001",
            ["view"] = "summary",
        },
    };

    private static BankingAuthorization AllowedAuthorization() => new(
        "transaction-001",
        "action-001",
        "chain-001",
        "allow",
        "bank_policy_allowed",
        "inline_allowed",
        "decision-receipt-001",
        TestPayloads.CanonicalAction);

    private static BankingAuthorization BlockedAuthorization() => AllowedAuthorization() with
    {
        Decision = "block",
        ReasonCode = "bank_customer_scope_mismatch",
        ControlMode = "inline_prevented",
    };
}

internal sealed class StubMaterialFactory(BankingActionRequest request)
    : IBankingActionMaterialFactory
{
    internal int CallCount { get; private set; }

    public BankingActionRequest Create(AIAgent agent, FunctionInvocationContext context)
    {
        CallCount++;
        return request;
    }
}

internal sealed class ContextAccountMaterialFactory : IBankingActionMaterialFactory
{
    public BankingActionRequest Create(AIAgent agent, FunctionInvocationContext context)
    {
        object? value = context.Arguments["account_id"];
        string accountId = value switch
        {
            string text => text,
            System.Text.Json.JsonElement element =>
                element.GetString() ?? throw new InvalidOperationException(),
            _ => throw new InvalidOperationException(),
        };
        return TestPayloads.WithAccount(TestPayloads.OwnAccountRequest, accountId);
    }
}
