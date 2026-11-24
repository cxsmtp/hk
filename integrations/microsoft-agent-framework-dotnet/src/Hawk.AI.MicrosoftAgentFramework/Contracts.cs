using System.Collections.ObjectModel;
using System.Text.Json;

namespace Hawk.AI.MicrosoftAgentFramework;

/// <summary>
/// Exact, immutable banking function material submitted to Hawk before execution.
/// Raw subject and account values are transient request material and must not be logged or persisted by the adapter.
/// </summary>
public sealed class BankingActionRequest
{
    /// <summary>Creates and deep-freezes one exact banking action snapshot.</summary>
    /// <param name="SubjectAssertion">Short-lived assertion issued by the bank trust boundary.</param>
    /// <param name="AiTransactionId">Stable Hawk transaction identifier.</param>
    /// <param name="ActionId">Unique action identifier within the transaction.</param>
    /// <param name="ChainId">Agent delegation-chain identifier.</param>
    /// <param name="AiSystemId">Registered Hawk AI-system identifier.</param>
    /// <param name="SourceAgentId">Originating agent identifier.</param>
    /// <param name="DelegatedAgentIds">Ordered delegated-agent identifiers.</param>
    /// <param name="ActionType">Canonical Hawk action type.</param>
    /// <param name="OperationType">Exact business operation.</param>
    /// <param name="ToolName">Approved function or tool name.</param>
    /// <param name="ToolVersion">Approved function or tool version.</param>
    /// <param name="ToolSchemaFingerprint">Lowercase SHA-256 schema fingerprint.</param>
    /// <param name="Arguments">Validated function arguments, never prompt prose.</param>
    /// <param name="RequestedCustomerSubjectId">Customer subject requested by the function.</param>
    /// <param name="RequestedAccountId">Account requested by the function.</param>
    /// <param name="RequestedResource">Requested banking resource.</param>
    /// <param name="Destination">Actual execution destination.</param>
    /// <param name="WorkloadIdentity">Workload identity used for execution.</param>
    /// <param name="WorkloadIdentityType">Server-recognized workload identity type.</param>
    /// <param name="WorkloadAuthenticationMode">Workload authentication mode.</param>
    /// <param name="WorkloadIdentitySource">Identity source system.</param>
    /// <param name="WorkloadIdentityProvenance">Verified identity provenance.</param>
    /// <param name="SideEffectClass">Read-only, reversible, or persistent side-effect class.</param>
    /// <param name="PolicySnapshotId">Server-approved policy snapshot identifier.</param>
    /// <param name="TransportBinding">Optional exact Function, MCP, Toolbox, REST, OpenAPI, or APIM route binding.</param>
    public BankingActionRequest(
        string SubjectAssertion,
        string AiTransactionId,
        string ActionId,
        string ChainId,
        string AiSystemId,
        string SourceAgentId,
        IReadOnlyList<string> DelegatedAgentIds,
        string ActionType,
        string OperationType,
        string ToolName,
        string ToolVersion,
        string ToolSchemaFingerprint,
        IReadOnlyDictionary<string, object?> Arguments,
        string RequestedCustomerSubjectId,
        string RequestedAccountId,
        string RequestedResource,
        string Destination,
        string WorkloadIdentity,
        string WorkloadIdentityType,
        string WorkloadAuthenticationMode,
        string WorkloadIdentitySource,
        string WorkloadIdentityProvenance,
        string SideEffectClass,
        string PolicySnapshotId,
        HawkTransportBinding? TransportBinding = null)
    {
        this.SubjectAssertion = SubjectAssertion;
        this.AiTransactionId = AiTransactionId;
        this.ActionId = ActionId;
        this.ChainId = ChainId;
        this.AiSystemId = AiSystemId;
        this.SourceAgentId = SourceAgentId;
        this.DelegatedAgentIds = FreezeDelegatedAgents(DelegatedAgentIds);
        this.ActionType = ActionType;
        this.OperationType = OperationType;
        this.ToolName = ToolName;
        this.ToolVersion = ToolVersion;
        this.ToolSchemaFingerprint = ToolSchemaFingerprint;
        this.Arguments = FreezeArguments(Arguments);
        this.RequestedCustomerSubjectId = RequestedCustomerSubjectId;
        this.RequestedAccountId = RequestedAccountId;
        this.RequestedResource = RequestedResource;
        this.Destination = Destination;
        this.WorkloadIdentity = WorkloadIdentity;
        this.WorkloadIdentityType = WorkloadIdentityType;
        this.WorkloadAuthenticationMode = WorkloadAuthenticationMode;
        this.WorkloadIdentitySource = WorkloadIdentitySource;
        this.WorkloadIdentityProvenance = WorkloadIdentityProvenance;
        this.SideEffectClass = SideEffectClass;
        this.PolicySnapshotId = PolicySnapshotId;
        this.TransportBinding = TransportBinding;
    }

    /// <summary>Short-lived assertion issued by the bank trust boundary.</summary>
    public string SubjectAssertion { get; }
    /// <summary>Stable Hawk transaction identifier.</summary>
    public string AiTransactionId { get; }
    /// <summary>Unique action identifier within the transaction.</summary>
    public string ActionId { get; }
    /// <summary>Agent delegation-chain identifier.</summary>
    public string ChainId { get; }
    /// <summary>Registered Hawk AI-system identifier.</summary>
    public string AiSystemId { get; }
    /// <summary>Originating agent identifier.</summary>
    public string SourceAgentId { get; }
    /// <summary>Ordered, immutable delegated-agent identifiers.</summary>
    public IReadOnlyList<string> DelegatedAgentIds { get; }
    /// <summary>Canonical Hawk action type.</summary>
    public string ActionType { get; }
    /// <summary>Exact business operation.</summary>
    public string OperationType { get; }
    /// <summary>Approved function or tool name.</summary>
    public string ToolName { get; }
    /// <summary>Approved function or tool version.</summary>
    public string ToolVersion { get; }
    /// <summary>Lowercase SHA-256 schema fingerprint.</summary>
    public string ToolSchemaFingerprint { get; }
    /// <summary>Deep-frozen validated function arguments.</summary>
    public IReadOnlyDictionary<string, object?> Arguments { get; }
    /// <summary>Customer subject requested by the function.</summary>
    public string RequestedCustomerSubjectId { get; }
    /// <summary>Account requested by the function.</summary>
    public string RequestedAccountId { get; }
    /// <summary>Requested banking resource.</summary>
    public string RequestedResource { get; }
    /// <summary>Actual execution destination.</summary>
    public string Destination { get; }
    /// <summary>Workload identity used for execution.</summary>
    public string WorkloadIdentity { get; }
    /// <summary>Server-recognized workload identity type.</summary>
    public string WorkloadIdentityType { get; }
    /// <summary>Workload authentication mode.</summary>
    public string WorkloadAuthenticationMode { get; }
    /// <summary>Workload identity source.</summary>
    public string WorkloadIdentitySource { get; }
    /// <summary>Verified identity provenance.</summary>
    public string WorkloadIdentityProvenance { get; }
    /// <summary>Read-only, reversible, or persistent side-effect class.</summary>
    public string SideEffectClass { get; }
    /// <summary>Server-approved policy snapshot identifier.</summary>
    public string PolicySnapshotId { get; }
    /// <summary>Exact route binding, or null for the backward-compatible function default.</summary>
    public HawkTransportBinding? TransportBinding { get; }

    /// <summary>Returns correlation-only material; assertions, targets, and arguments are redacted.</summary>
    public override string ToString() =>
        $"BankingActionRequest {{ AiTransactionId = {AiTransactionId}, " +
        $"ActionId = {ActionId}, ToolName = {ToolName}, SensitiveMaterial = [REDACTED] }}";

    private static IReadOnlyList<string> FreezeDelegatedAgents(
        IReadOnlyList<string> delegatedAgentIds)
    {
        ArgumentNullException.ThrowIfNull(delegatedAgentIds);
        return Array.AsReadOnly(delegatedAgentIds.ToArray());
    }

    private static IReadOnlyDictionary<string, object?> FreezeArguments(
        IReadOnlyDictionary<string, object?> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        JsonElement serialized = JsonSerializer.SerializeToElement(
            arguments,
            BankingJson.Options);
        if (serialized.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException(
                "Banking function arguments must be a JSON object.",
                nameof(arguments));
        }

        var frozen = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (JsonProperty property in serialized.EnumerateObject())
        {
            frozen.Add(property.Name, property.Value.Clone());
        }

        return new ReadOnlyDictionary<string, object?>(frozen);
    }
}

/// <summary>
/// Hawk authorization outcome bound to an existing Decision Receipt.
/// </summary>
public sealed record BankingAuthorization(
    string AiTransactionId,
    string ActionId,
    string ChainId,
    string Decision,
    string ReasonCode,
    string ControlMode,
    string DecisionReceiptId,
    JsonElement CanonicalAction);

/// <summary>
/// Final server-side validation outcome immediately before function execution.
/// </summary>
public sealed record PreExecutionResult(
    bool Executable,
    string? IntegrityResultId,
    string? ExecutionGrantId,
    DateTimeOffset? GrantExpiresAt);

/// <summary>
/// Existing Hawk Execution Receipt and authorization-integrity comparison.
/// </summary>
public sealed record ExecutionResult(
    string ExecutionReceiptId,
    string IntegrityResultId,
    string Integrity,
    IReadOnlyList<string> DriftFields);

/// <summary>
/// Supplies a short-lived access token for one request. Implementations must not persist plaintext tokens.
/// </summary>
public interface IHawkAccessTokenProvider
{
    /// <summary>
    /// Returns a token for the current request only.
    /// </summary>
    ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Minimal Hawk banking authorization contract used by the framework-independent final gate.
/// </summary>
public interface IHawkBankingControlClient
{
    /// <summary>Authorizes exact preliminary banking material.</summary>
    Task<BankingAuthorization> AuthorizeAsync(
        BankingActionRequest request,
        CancellationToken cancellationToken);

    /// <summary>Revalidates exact canonical material immediately before execution.</summary>
    Task<PreExecutionResult> ValidatePreExecutionAsync(
        string decisionReceiptId,
        string executionAttemptId,
        BankingActionRequest finalAction,
        CancellationToken cancellationToken);

    /// <summary>Reports the actual execution through Hawk's existing receipt API.</summary>
    Task<ExecutionResult> ReportExecutionAsync(
        string decisionReceiptId,
        string executionGrantId,
        string executionAttemptId,
        string executionStatus,
        CancellationToken cancellationToken);
}

/// <summary>Exact, prompt-free model request material sent to Hawk before provider invocation.</summary>
public sealed class ModelRequestMaterial
{
    /// <summary>Creates and deep-freezes one model authorization request.</summary>
    public ModelRequestMaterial(
        string SubjectAssertion,
        string AiTransactionId,
        string ActionId,
        string RunId,
        string ChainId,
        string AiSystemId,
        string SourceAgentId,
        IReadOnlyList<string> DelegatedAgentIds,
        string Provider,
        string Deployment,
        string Model,
        string RequestClassification,
        string SessionId,
        bool Streaming,
        string Destination,
        string RequestHash,
        string WorkloadIdentity,
        string WorkloadIdentityType,
        string WorkloadAuthenticationMode,
        string WorkloadIdentitySource,
        string WorkloadIdentityProvenance,
        string PolicySnapshotId)
    {
        this.SubjectAssertion = Require(SubjectAssertion, nameof(SubjectAssertion), 16_384);
        this.AiTransactionId = Require(AiTransactionId, nameof(AiTransactionId), 64);
        this.ActionId = Require(ActionId, nameof(ActionId), 64);
        this.RunId = Require(RunId, nameof(RunId), 128);
        this.ChainId = Require(ChainId, nameof(ChainId), 64);
        this.AiSystemId = Require(AiSystemId, nameof(AiSystemId), 64);
        this.SourceAgentId = Require(SourceAgentId, nameof(SourceAgentId), 128);
        this.DelegatedAgentIds = Array.AsReadOnly(DelegatedAgentIds?.ToArray()
            ?? throw new ArgumentNullException(nameof(DelegatedAgentIds)));
        this.Provider = Require(Provider, nameof(Provider), 128);
        this.Deployment = Require(Deployment, nameof(Deployment), 128);
        this.Model = Require(Model, nameof(Model), 128);
        this.RequestClassification = Require(
            RequestClassification,
            nameof(RequestClassification),
            64);
        this.SessionId = Require(SessionId, nameof(SessionId), 128);
        this.Streaming = Streaming;
        this.Destination = Require(Destination, nameof(Destination), 512);
        this.RequestHash = Hash(RequestHash, nameof(RequestHash));
        this.WorkloadIdentity = Require(WorkloadIdentity, nameof(WorkloadIdentity), 256);
        this.WorkloadIdentityType = Require(
            WorkloadIdentityType,
            nameof(WorkloadIdentityType),
            64);
        this.WorkloadAuthenticationMode = Require(
            WorkloadAuthenticationMode,
            nameof(WorkloadAuthenticationMode),
            64);
        this.WorkloadIdentitySource = Require(
            WorkloadIdentitySource,
            nameof(WorkloadIdentitySource),
            128);
        this.WorkloadIdentityProvenance = Require(
            WorkloadIdentityProvenance,
            nameof(WorkloadIdentityProvenance),
            64);
        this.PolicySnapshotId = Require(PolicySnapshotId, nameof(PolicySnapshotId), 64);
    }

    /// <summary>Short-lived bank assertion; never persisted by the adapter.</summary>
    public string SubjectAssertion { get; }
    /// <summary>End-to-end transaction identifier.</summary>
    public string AiTransactionId { get; }
    /// <summary>Model action identifier.</summary>
    public string ActionId { get; }
    /// <summary>Agent Run identifier.</summary>
    public string RunId { get; }
    /// <summary>Agent chain identifier.</summary>
    public string ChainId { get; }
    /// <summary>Registered Hawk AI system.</summary>
    public string AiSystemId { get; }
    /// <summary>Originating agent.</summary>
    public string SourceAgentId { get; }
    /// <summary>Ordered delegated agents.</summary>
    public IReadOnlyList<string> DelegatedAgentIds { get; }
    /// <summary>Model provider.</summary>
    public string Provider { get; }
    /// <summary>Provider deployment.</summary>
    public string Deployment { get; }
    /// <summary>Model identifier.</summary>
    public string Model { get; }
    /// <summary>Trusted request classification.</summary>
    public string RequestClassification { get; }
    /// <summary>Conversation/session identifier.</summary>
    public string SessionId { get; }
    /// <summary>Whether buffered streaming was requested.</summary>
    public bool Streaming { get; }
    /// <summary>Provider destination.</summary>
    public string Destination { get; }
    /// <summary>Prompt-free request SHA-256.</summary>
    public string RequestHash { get; }
    /// <summary>Execution workload identity.</summary>
    public string WorkloadIdentity { get; }
    /// <summary>Server-recognized workload identity type.</summary>
    public string WorkloadIdentityType { get; }
    /// <summary>Authentication mode.</summary>
    public string WorkloadAuthenticationMode { get; }
    /// <summary>Identity source system.</summary>
    public string WorkloadIdentitySource { get; }
    /// <summary>Verified identity provenance.</summary>
    public string WorkloadIdentityProvenance { get; }
    /// <summary>Expected Hawk policy snapshot.</summary>
    public string PolicySnapshotId { get; }

    /// <summary>Returns correlation only and redacts the assertion.</summary>
    public override string ToString() =>
        $"ModelRequestMaterial {{ AiTransactionId = {AiTransactionId}, ActionId = {ActionId}, " +
        $"Model = {Model}, SensitiveMaterial = [REDACTED] }}";

    private static string Require(string value, string parameterName, int maximum)
    {
        string normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length == 0 || normalized.Length > maximum)
        {
            throw new ArgumentException("A bounded non-empty value is required.", parameterName);
        }

        return normalized;
    }

    private static string Hash(string value, string parameterName)
    {
        string normalized = Require(value, parameterName, 64);
        if (normalized.Length != 64 || normalized.Any(character =>
                !char.IsAsciiHexDigit(character) || char.IsUpper(character)))
        {
            throw new ArgumentException("A lowercase SHA-256 value is required.", parameterName);
        }

        return normalized;
    }
}

/// <summary>Hawk's pre-provider model authorization and existing Decision Receipt reference.</summary>
public sealed record ModelAuthorization(
    string AiTransactionId,
    string ActionId,
    string ChainId,
    string Decision,
    string ReasonCode,
    string ControlMode,
    string DecisionReceiptId,
    bool ModelBindingVerified,
    bool StreamingCovered);

/// <summary>Prompt-free model response material correlated to the request Decision Receipt.</summary>
public sealed record ModelResponseMaterial(
    string DecisionReceiptId,
    string AiTransactionId,
    string ActionId,
    string ChainId,
    string ResponseHash,
    string ResponseClassification,
    bool Streaming,
    string FinishReason);

/// <summary>Deterministic Hawk response handling outcome.</summary>
public sealed record ModelResponseValidation(
    string Decision,
    string ReasonCode,
    string ControlMode,
    string? SafeResponse,
    bool EvidenceComplete,
    string DecisionReceiptId);

/// <summary>Hawk's model-path control contract, independent from function authorization.</summary>
public interface IHawkModelControlClient
{
    /// <summary>Authorizes exact model request material before provider invocation.</summary>
    Task<ModelAuthorization> AuthorizeModelRequestAsync(
        ModelRequestMaterial request,
        CancellationToken cancellationToken);

    /// <summary>Validates prompt-free model response material before release.</summary>
    Task<ModelResponseValidation> ValidateModelResponseAsync(
        ModelResponseMaterial response,
        CancellationToken cancellationToken);
}

internal sealed record BankingPreExecutionRequest(
    string DecisionReceiptId,
    string ExecutionAttemptId,
    BankingActionRequest FinalAction);

internal sealed record BankingExecutionRequest(
    string DecisionReceiptId,
    string ExecutionGrantId,
    string ExecutionAttemptId,
    string ExecutionStatus);
