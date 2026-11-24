namespace Hawk.AI.MicrosoftAgentFramework;

/// <summary>
/// Immutable Agent Run correlation and delegated authority. This establishes run context;
/// it is not itself exact tool authorization.
/// </summary>
public sealed class HawkAgentRunContext
{
    /// <summary>Creates a subject- and purpose-bound Agent Run.</summary>
    public HawkAgentRunContext(
        SubjectExecutionContext Subject,
        string AiTransactionId,
        string RunId,
        string ChainId,
        string AiSystemId,
        string AgentId,
        IReadOnlyList<string> AgentLineage,
        IReadOnlyList<string> EffectiveAuthority,
        string BusinessPurposeId,
        string ConversationId,
        string ModelProvider,
        string ModelDeployment,
        string ModelName,
        string Destination,
        string RequestClassification,
        string PolicySnapshotId)
    {
        ArgumentNullException.ThrowIfNull(Subject);
        this.Subject = Subject;
        this.AiTransactionId = Text(AiTransactionId, nameof(AiTransactionId), 64);
        this.RunId = Text(RunId, nameof(RunId), 128);
        this.ChainId = Text(ChainId, nameof(ChainId), 64);
        this.AiSystemId = Text(AiSystemId, nameof(AiSystemId), 64);
        this.AgentId = Text(AgentId, nameof(AgentId), 128);
        this.AgentLineage = Freeze(AgentLineage, nameof(AgentLineage), 32);
        if (!string.Equals(this.AgentLineage[^1], this.AgentId, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Agent lineage must terminate at the active agent.",
                nameof(AgentLineage));
        }

        this.EffectiveAuthority = Freeze(
            EffectiveAuthority,
            nameof(EffectiveAuthority),
            100);
        if (!this.EffectiveAuthority.All(Subject.AuthorityScope.Contains))
        {
            throw new InvalidOperationException("AUTHORITY_EXPANSION");
        }

        this.BusinessPurposeId = Text(BusinessPurposeId, nameof(BusinessPurposeId), 128);
        if (!string.Equals(this.BusinessPurposeId, Subject.PurposeId, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Agent Run purpose must match authoritative subject purpose.",
                nameof(BusinessPurposeId));
        }

        this.ConversationId = Text(ConversationId, nameof(ConversationId), 128);
        this.ModelProvider = Text(ModelProvider, nameof(ModelProvider), 128);
        this.ModelDeployment = Text(ModelDeployment, nameof(ModelDeployment), 128);
        this.ModelName = Text(ModelName, nameof(ModelName), 128);
        this.Destination = Text(Destination, nameof(Destination), 512);
        this.RequestClassification = Text(
            RequestClassification,
            nameof(RequestClassification),
            64);
        this.PolicySnapshotId = Text(PolicySnapshotId, nameof(PolicySnapshotId), 64);
    }

    /// <summary>Authoritative subject context.</summary>
    public SubjectExecutionContext Subject { get; }
    /// <summary>End-to-end AI transaction identifier.</summary>
    public string AiTransactionId { get; }
    /// <summary>Current Agent Run identifier.</summary>
    public string RunId { get; }
    /// <summary>Delegation-chain identifier.</summary>
    public string ChainId { get; }
    /// <summary>Registered Hawk AI system.</summary>
    public string AiSystemId { get; }
    /// <summary>Current agent.</summary>
    public string AgentId { get; }
    /// <summary>Ordered agent delegation lineage.</summary>
    public IReadOnlyList<string> AgentLineage { get; }
    /// <summary>Attenuated authority available to the current agent.</summary>
    public IReadOnlyList<string> EffectiveAuthority { get; }
    /// <summary>Authoritative business purpose.</summary>
    public string BusinessPurposeId { get; }
    /// <summary>Conversation/session correlation.</summary>
    public string ConversationId { get; }
    /// <summary>Model provider.</summary>
    public string ModelProvider { get; }
    /// <summary>Provider deployment.</summary>
    public string ModelDeployment { get; }
    /// <summary>Model identifier.</summary>
    public string ModelName { get; }
    /// <summary>Model request destination.</summary>
    public string Destination { get; }
    /// <summary>Trusted request data classification.</summary>
    public string RequestClassification { get; }
    /// <summary>Expected Hawk policy snapshot.</summary>
    public string PolicySnapshotId { get; }

    /// <summary>Creates a child run whose authority can only be equal to or narrower than its parent.</summary>
    public HawkAgentRunContext CreateDelegatedRun(
        string childAgentId,
        string childRunId,
        IReadOnlyList<string> requestedAuthority)
    {
        IReadOnlyList<string> childAuthority = Freeze(
            requestedAuthority,
            nameof(requestedAuthority),
            100);
        if (!childAuthority.All(EffectiveAuthority.Contains))
        {
            throw new InvalidOperationException("AUTHORITY_EXPANSION");
        }

        return new HawkAgentRunContext(
            Subject,
            AiTransactionId,
            childRunId,
            ChainId,
            AiSystemId,
            childAgentId,
            AgentLineage.Append(childAgentId).ToArray(),
            childAuthority,
            BusinessPurposeId,
            ConversationId,
            ModelProvider,
            ModelDeployment,
            ModelName,
            Destination,
            RequestClassification,
            PolicySnapshotId);
    }

    /// <summary>Returns only safe run correlation; subject and account values are redacted.</summary>
    public override string ToString() =>
        $"HawkAgentRunContext {{ AiTransactionId = {AiTransactionId}, RunId = {RunId}, " +
        $"ChainId = {ChainId}, AgentId = {AgentId}, Subject = [REDACTED] }}";

    private static string Text(string value, string name, int maximum) =>
        AuthorizedResourceScope.RequireText(value, name, maximum);

    private static IReadOnlyList<string> Freeze(
        IReadOnlyList<string> values,
        string name,
        int maximum) =>
        AuthorizedResourceScope.FreezeUnique(values, name, maximum);
}
