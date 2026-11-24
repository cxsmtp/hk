using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using System.Text.Json;

namespace Hawk.AI.MicrosoftAgentFramework;

/// <summary>
/// Creates exact Hawk banking material from trusted bank context and validated function arguments.
/// Implementations must use <see cref="FunctionInvocationContext.Arguments"/>, not prompt prose or model output,
/// for consequential function parameters.
/// </summary>
public interface IBankingActionMaterialFactory
{
    /// <summary>
    /// Creates immutable authorization material from the current function invocation and bank-issued context.
    /// </summary>
    BankingActionRequest Create(AIAgent agent, FunctionInvocationContext context);
}

/// <summary>
/// Thin Microsoft Agent Framework function-invocation adapter over Hawk's final execution gate.
/// </summary>
public sealed class HawkAgentFrameworkMiddleware
{
    private readonly HawkFunctionExecutionGate _gate;
    private readonly IBankingActionMaterialFactory _materialFactory;

    /// <summary>Creates the exact function middleware adapter.</summary>
    public HawkAgentFrameworkMiddleware(
        HawkFunctionExecutionGate gate,
        IBankingActionMaterialFactory materialFactory)
    {
        ArgumentNullException.ThrowIfNull(gate);
        ArgumentNullException.ThrowIfNull(materialFactory);
        _gate = gate;
        _materialFactory = materialFactory;
    }

    /// <summary>
    /// Microsoft Agent Framework 1.15.0 function middleware callback.
    /// A denied result is returned without invoking <paramref name="next"/>.
    /// </summary>
    public ValueTask<object?> InvokeAsync(
        AIAgent agent,
        FunctionInvocationContext context,
        Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>> next,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);
        BankingActionRequest preliminary = _materialFactory.Create(agent, context);
        return InvokeCoreAsync(
            agent,
            context,
            preliminary,
            next,
            cancellationToken);
    }

    private async ValueTask<object?> InvokeCoreAsync(
        AIAgent agent,
        FunctionInvocationContext context,
        BankingActionRequest preliminary,
        Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>> next,
        CancellationToken cancellationToken)
    {
        FunctionInvocationContext? sealedContext = null;
        HawkFunctionResult result = await _gate
            .ExecuteAsync(
                preliminary,
                finalMaterial: () =>
                {
                    sealedContext = CreateSealedContext(context);
                    BankingActionRequest final = _materialFactory.Create(
                        agent,
                        sealedContext);
                    EnsureArgumentsMatch(sealedContext.Arguments, final.Arguments);
                    return final;
                },
                next: token => InvokeSealedNextAsync(
                    context,
                    sealedContext
                        ?? throw new InvalidOperationException(
                            "Hawk sealed invocation context is unavailable."),
                    next,
                    token),
                cancellationToken)
            .ConfigureAwait(false);
        if (result.Executed)
        {
            return result.Output;
        }

        return result.Denial ?? new HawkToolDeniedResult(
            result.Decision,
            result.ReasonCode,
            "inline_prevented",
            result.DecisionReceiptId,
            result.IntegrityResultId);
    }

    private static async ValueTask<object?> InvokeSealedNextAsync(
        FunctionInvocationContext originalContext,
        FunctionInvocationContext sealedContext,
        Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>> next,
        CancellationToken cancellationToken)
    {
        object? result = await next(sealedContext, cancellationToken).ConfigureAwait(false);
        originalContext.Terminate = sealedContext.Terminate;
        return result;
    }

    private static FunctionInvocationContext CreateSealedContext(
        FunctionInvocationContext source)
    {
        if (source.Arguments.Context is { Count: > 0 })
        {
            throw new InvalidOperationException(
                "Hawk banking functions do not permit unbound argument context.");
        }

        AIFunctionArguments executionArguments = CloneArguments(source.Arguments);
        AIFunctionArguments exposedArguments = CloneArguments(source.Arguments);
        AIFunction originalFunction = source.Function;
        AIFunction sealedFunction = AIFunctionFactory.Create(
            (Func<CancellationToken, ValueTask<object?>>)(token =>
                originalFunction.InvokeAsync(executionArguments, token)),
            new AIFunctionFactoryOptions
            {
                Name = originalFunction.Name,
                Description = originalFunction.Description,
            });
        return new FunctionInvocationContext
        {
            Function = sealedFunction,
            Arguments = exposedArguments,
            CallContent = source.CallContent,
            Messages = source.Messages,
            Options = source.Options,
            Iteration = source.Iteration,
            FunctionCallIndex = source.FunctionCallIndex,
            FunctionCount = source.FunctionCount,
            Terminate = source.Terminate,
            IsStreaming = source.IsStreaming,
        };
    }

    private static AIFunctionArguments CloneArguments(AIFunctionArguments source)
    {
        JsonElement root = JsonSerializer.SerializeToElement(source, BankingJson.Options);
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException(
                "Hawk banking function arguments must be a JSON object.");
        }

        var values = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (JsonProperty property in root.EnumerateObject())
        {
            values.Add(property.Name, property.Value.Clone());
        }

        return new AIFunctionArguments(values)
        {
            Services = source.Services,
        };
    }

    private static void EnsureArgumentsMatch(
        AIFunctionArguments sealedArguments,
        IReadOnlyDictionary<string, object?> actionArguments)
    {
        string sealedJson = JsonSerializer.Serialize(sealedArguments, BankingJson.Options);
        string actionJson = JsonSerializer.Serialize(actionArguments, BankingJson.Options);
        if (!string.Equals(sealedJson, actionJson, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Hawk banking material does not match the sealed function arguments.");
        }
    }
}
