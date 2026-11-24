using Microsoft.Extensions.AI;
using System.Security.Cryptography;
using System.Text.Json;

namespace Hawk.AI.MicrosoftAgentFramework;

/// <summary>Supplies a fresh short-lived bank subject assertion for one Hawk request.</summary>
public interface IHawkSubjectAssertionProvider
{
    /// <summary>Returns an assertion from the trusted bank boundary without persisting it.</summary>
    ValueTask<string> GetSubjectAssertionAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Trusted deterministic classification boundary. Model output cannot classify itself;
/// implementations must derive classifications from enterprise controls.
/// </summary>
public interface IHawkModelClassificationProvider
{
    /// <summary>Classifies the exact request before provider invocation.</summary>
    string ClassifyRequest(IReadOnlyList<ChatMessage> messages, ChatOptions? options);

    /// <summary>Classifies the exact response before release.</summary>
    string ClassifyResponse(ChatResponse response);
}

/// <summary>Verified workload identity material for the model provider call.</summary>
public sealed record HawkModelRuntimeIdentity(
    string WorkloadIdentity,
    string WorkloadIdentityType,
    string WorkloadAuthenticationMode,
    string WorkloadIdentitySource,
    string WorkloadIdentityProvenance);

/// <summary>
/// Default prompt-free material factory. Prompt and response content is hashed in memory
/// and never retained in the resulting Hawk contracts.
/// </summary>
public sealed class HawkHashingModelMaterialFactory : IHawkModelMaterialFactory
{
    private static readonly HashSet<string> Classifications = new(StringComparer.Ordinal)
    {
        "public",
        "internal",
        "confidential",
        "restricted",
    };

    private readonly IHawkSubjectAssertionProvider _assertions;
    private readonly IHawkModelClassificationProvider _classifications;
    private readonly HawkModelRuntimeIdentity _identity;
    private readonly Func<string> _actionIdFactory;

    /// <summary>Creates a factory over trusted assertion, classification, and identity providers.</summary>
    public HawkHashingModelMaterialFactory(
        IHawkSubjectAssertionProvider assertions,
        IHawkModelClassificationProvider classifications,
        HawkModelRuntimeIdentity identity,
        Func<string>? actionIdFactory = null)
    {
        ArgumentNullException.ThrowIfNull(assertions);
        ArgumentNullException.ThrowIfNull(classifications);
        ArgumentNullException.ThrowIfNull(identity);
        _assertions = assertions;
        _classifications = classifications;
        _identity = identity;
        _actionIdFactory = actionIdFactory ?? (() => $"model:{Guid.NewGuid():N}");
    }

    /// <inheritdoc />
    public async ValueTask<ModelRequestMaterial> CreateRequestAsync(
        HawkAgentRunContext run,
        IReadOnlyList<ChatMessage> messages,
        ChatOptions? options,
        bool streaming,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(run);
        ArgumentNullException.ThrowIfNull(messages);
        string assertion = await _assertions
            .GetSubjectAssertionAsync(cancellationToken)
            .ConfigureAwait(false);
        string classification = RequireClassification(
            _classifications.ClassifyRequest(messages, options));
        if (!string.Equals(
                classification,
                run.RequestClassification,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Trusted request classification does not match Agent Run binding.");
        }

        return new ModelRequestMaterial(
            assertion,
            run.AiTransactionId,
            _actionIdFactory(),
            run.RunId,
            run.ChainId,
            run.AiSystemId,
            run.AgentId,
            run.AgentLineage.Skip(1).ToArray(),
            run.ModelProvider,
            run.ModelDeployment,
            run.ModelName,
            classification,
            run.ConversationId,
            streaming,
            run.Destination,
            Hash(new
            {
                Messages = messages,
                Options = options,
                run.ModelProvider,
                run.ModelDeployment,
                run.ModelName,
                run.Destination,
                Streaming = streaming,
            }),
            _identity.WorkloadIdentity,
            _identity.WorkloadIdentityType,
            _identity.WorkloadAuthenticationMode,
            _identity.WorkloadIdentitySource,
            _identity.WorkloadIdentityProvenance,
            run.PolicySnapshotId);
    }

    /// <inheritdoc />
    public ModelResponseMaterial CreateResponse(
        HawkAgentRunContext run,
        ModelRequestMaterial request,
        ModelAuthorization authorization,
        ChatResponse response,
        bool streaming)
    {
        ArgumentNullException.ThrowIfNull(run);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(response);
        string classification = RequireClassification(
            _classifications.ClassifyResponse(response));
        return new ModelResponseMaterial(
            authorization.DecisionReceiptId,
            run.AiTransactionId,
            request.ActionId,
            run.ChainId,
            Hash(response),
            classification,
            streaming,
            response.FinishReason?.Value ?? "unknown");
    }

    private static string RequireClassification(string value)
    {
        string normalized = value?.Trim().ToLowerInvariant() ?? string.Empty;
        if (!Classifications.Contains(normalized))
        {
            throw new InvalidOperationException(
                "Trusted model classification is unavailable or invalid.");
        }

        return normalized;
    }

    private static string Hash<T>(T value)
    {
        byte[] serialized = JsonSerializer.SerializeToUtf8Bytes(value, BankingJson.Options);
        return Convert.ToHexString(SHA256.HashData(serialized)).ToLowerInvariant();
    }
}
