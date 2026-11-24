using Microsoft.Extensions.AI;
using System.Runtime.CompilerServices;

namespace Hawk.AI.MicrosoftAgentFramework;

/// <summary>Streaming response behavior for the model control wrapper.</summary>
public enum HawkStreamingControlMode
{
    /// <summary>No streaming provider call occurs because token-by-token response assurance is unavailable.</summary>
    FailClosed,
    /// <summary>The full bounded response is buffered and validated before any update is released.</summary>
    BufferUntilValidated,
}

/// <summary>Creates prompt-free request and response material for Hawk.</summary>
public interface IHawkModelMaterialFactory
{
    /// <summary>Creates exact prompt-free model request material.</summary>
    ValueTask<ModelRequestMaterial> CreateRequestAsync(
        HawkAgentRunContext run,
        IReadOnlyList<ChatMessage> messages,
        ChatOptions? options,
        bool streaming,
        CancellationToken cancellationToken);

    /// <summary>Creates exact response hashes and classifications without persisting response text.</summary>
    ModelResponseMaterial CreateResponse(
        HawkAgentRunContext run,
        ModelRequestMaterial request,
        ModelAuthorization authorization,
        ChatResponse response,
        bool streaming);
}

/// <summary>Safe exception proving a model request was denied before provider invocation.</summary>
public sealed class HawkModelRequestDeniedException : InvalidOperationException
{
    internal HawkModelRequestDeniedException(ModelAuthorization authorization)
        : base("Hawk blocked the model request before provider invocation.")
    {
        Decision = authorization.Decision;
        ReasonCode = authorization.ReasonCode;
        DecisionReceiptId = authorization.DecisionReceiptId;
    }

    /// <summary>Hawk decision.</summary>
    public string Decision { get; }
    /// <summary>Stable reason code.</summary>
    public string ReasonCode { get; }
    /// <summary>Existing Hawk Decision Receipt.</summary>
    public string DecisionReceiptId { get; }
}

/// <summary>Safe exception proving provider output was withheld after response control.</summary>
public sealed class HawkModelResponseDeniedException : InvalidOperationException
{
    internal HawkModelResponseDeniedException(ModelResponseValidation validation)
        : base("Hawk withheld the model response after deterministic response control.")
    {
        Decision = validation.Decision;
        ReasonCode = validation.ReasonCode;
        DecisionReceiptId = validation.DecisionReceiptId;
    }

    /// <summary>Hawk response decision.</summary>
    public string Decision { get; }
    /// <summary>Stable response reason.</summary>
    public string ReasonCode { get; }
    /// <summary>Correlated request Decision Receipt.</summary>
    public string DecisionReceiptId { get; }
}

/// <summary>Streaming is explicitly not covered and no provider request occurred.</summary>
public sealed class HawkStreamingNotCoveredException : InvalidOperationException
{
    internal HawkStreamingNotCoveredException()
        : base("Hawk streaming response control is not enabled; provider invocation was prevented.")
    {
    }
}

/// <summary>
/// Microsoft.Extensions.AI model-path middleware. Model request authorization remains
/// independent from function authorization. Default streaming behavior fails closed.
/// </summary>
public sealed class HawkChatClient : DelegatingChatClient
{
    private static readonly HashSet<string> ExecutableDecisions = new(StringComparer.Ordinal)
    {
        "allow",
        "warn",
    };

    private readonly IHawkModelControlClient _hawk;
    private readonly HawkAgentRunContext _run;
    private readonly IHawkModelMaterialFactory _materialFactory;
    private readonly HawkStreamingControlMode _streamingMode;
    private readonly int _maxBufferedCharacters;

    /// <summary>Creates model-path middleware over an existing chat client.</summary>
    public HawkChatClient(
        IChatClient innerClient,
        IHawkModelControlClient hawk,
        HawkAgentRunContext run,
        IHawkModelMaterialFactory materialFactory,
        HawkStreamingControlMode streamingMode = HawkStreamingControlMode.FailClosed,
        int maxBufferedCharacters = 1_000_000)
        : base(innerClient)
    {
        ArgumentNullException.ThrowIfNull(hawk);
        ArgumentNullException.ThrowIfNull(run);
        ArgumentNullException.ThrowIfNull(materialFactory);
        if (maxBufferedCharacters is < 1 or > 10_000_000)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBufferedCharacters));
        }

        _hawk = hawk;
        _run = run;
        _materialFactory = materialFactory;
        _streamingMode = streamingMode;
        _maxBufferedCharacters = maxBufferedCharacters;
    }

    /// <inheritdoc />
    public override async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<ChatMessage> frozenMessages = FreezeMessages(messages);
        ModelRequestMaterial material = await _materialFactory
            .CreateRequestAsync(
                _run,
                frozenMessages,
                options,
                streaming: false,
                cancellationToken)
            .ConfigureAwait(false);
        ModelAuthorization authorization = await AuthorizeAsync(material, cancellationToken)
            .ConfigureAwait(false);
        ChatResponse response = await base
            .GetResponseAsync(frozenMessages, options, cancellationToken)
            .ConfigureAwait(false);
        return await ValidateResponseAsync(
                material,
                authorization,
                response,
                streaming: false,
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (_streamingMode != HawkStreamingControlMode.BufferUntilValidated)
        {
            throw new HawkStreamingNotCoveredException();
        }

        IReadOnlyList<ChatMessage> frozenMessages = FreezeMessages(messages);
        ModelRequestMaterial material = await _materialFactory
            .CreateRequestAsync(
                _run,
                frozenMessages,
                options,
                streaming: true,
                cancellationToken)
            .ConfigureAwait(false);
        ModelAuthorization authorization = await AuthorizeAsync(material, cancellationToken)
            .ConfigureAwait(false);
        var buffered = new List<ChatResponseUpdate>();
        var characters = 0;
        await foreach (ChatResponseUpdate update in base
            .GetStreamingResponseAsync(frozenMessages, options, cancellationToken)
            .WithCancellation(cancellationToken)
            .ConfigureAwait(false))
        {
            characters = checked(characters + (update.Text?.Length ?? 0));
            if (characters > _maxBufferedCharacters)
            {
                throw new InvalidOperationException(
                    "Hawk buffered streaming response exceeded its safety limit.");
            }

            buffered.Add(update.Clone());
        }

        ChatResponse response = buffered.ToChatResponse();
        ChatResponse validated = await ValidateResponseAsync(
                material,
                authorization,
                response,
                streaming: true,
                cancellationToken)
            .ConfigureAwait(false);
        if (ReferenceEquals(validated, response))
        {
            foreach (ChatResponseUpdate update in buffered)
            {
                yield return update;
            }

            yield break;
        }

        yield return new ChatResponseUpdate(ChatRole.Assistant, validated.Text);
    }

    private async Task<ModelAuthorization> AuthorizeAsync(
        ModelRequestMaterial material,
        CancellationToken cancellationToken)
    {
        ModelAuthorization authorization = await _hawk
            .AuthorizeModelRequestAsync(material, cancellationToken)
            .ConfigureAwait(false);
        EnsureCorrelation(material, authorization);
        if (!ExecutableDecisions.Contains(authorization.Decision))
        {
            throw new HawkModelRequestDeniedException(authorization);
        }

        if (material.Streaming && !authorization.StreamingCovered)
        {
            throw new HawkStreamingNotCoveredException();
        }

        return authorization;
    }

    private async Task<ChatResponse> ValidateResponseAsync(
        ModelRequestMaterial request,
        ModelAuthorization authorization,
        ChatResponse response,
        bool streaming,
        CancellationToken cancellationToken)
    {
        ModelResponseMaterial material = _materialFactory.CreateResponse(
            _run,
            request,
            authorization,
            response,
            streaming);
        ModelResponseValidation validation = await _hawk
            .ValidateModelResponseAsync(material, cancellationToken)
            .ConfigureAwait(false);
        if (!string.Equals(
                validation.DecisionReceiptId,
                authorization.DecisionReceiptId,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException("Hawk model response correlation is invalid.");
        }

        return validation.Decision switch
        {
            "allow" => response,
            "redact" or "safe_fallback" when !string.IsNullOrWhiteSpace(validation.SafeResponse) =>
                new ChatResponse(new ChatMessage(ChatRole.Assistant, validation.SafeResponse)),
            "block" => throw new HawkModelResponseDeniedException(validation),
            "regenerate" => throw new InvalidOperationException(
                "Hawk requested bounded regeneration, but no regeneration policy is configured."),
            _ => throw new InvalidDataException("Hawk returned an invalid model response decision."),
        };
    }

    private static IReadOnlyList<ChatMessage> FreezeMessages(IEnumerable<ChatMessage> messages)
    {
        ArgumentNullException.ThrowIfNull(messages);
        ChatMessage[] frozen = messages.Select(message => message.Clone()).ToArray();
        if (frozen.Length == 0)
        {
            throw new ArgumentException("At least one chat message is required.", nameof(messages));
        }

        return Array.AsReadOnly(frozen);
    }

    private static void EnsureCorrelation(
        ModelRequestMaterial request,
        ModelAuthorization authorization)
    {
        if (
            !string.Equals(
                request.AiTransactionId,
                authorization.AiTransactionId,
                StringComparison.Ordinal)
            || !string.Equals(request.ActionId, authorization.ActionId, StringComparison.Ordinal)
            || !string.Equals(request.ChainId, authorization.ChainId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Hawk model authorization correlation is invalid.");
        }
    }
}
