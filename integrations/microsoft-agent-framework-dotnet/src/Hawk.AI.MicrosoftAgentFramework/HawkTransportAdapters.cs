namespace Hawk.AI.MicrosoftAgentFramework;

/// <summary>
/// Immutable, route-specific execution material sent with the existing banking action.
/// It selects no policy and grants no authority.
/// </summary>
public sealed class HawkTransportBinding
{
    private static readonly HashSet<string> SupportedTransports = new(StringComparer.Ordinal)
    {
        "function",
        "mcp",
        "toolbox",
        "rest",
        "openapi",
        "apim",
    };

    /// <summary>Creates one exact transport binding and rejects incomplete route material.</summary>
    public HawkTransportBinding(
        string Transport,
        string RouteId,
        string AuthenticationMode,
        bool DirectBypass = false,
        string? FunctionManifestId = null,
        string? McpServerId = null,
        string? McpToolName = null,
        string? McpToolVersion = null,
        string? McpToolFingerprintId = null,
        string? ToolboxId = null,
        string? ToolboxVersion = null,
        string? ProjectConnectionId = null,
        string? HttpMethod = null,
        string? RouteTemplate = null,
        string? OpenapiOperationId = null,
        string? OpenapiDocumentFingerprint = null,
        string? ApimApiId = null,
        string? ApimRevision = null,
        string? ApimBackendId = null)
    {
        this.Transport = Require(Transport, nameof(Transport), 32).ToLowerInvariant();
        if (!SupportedTransports.Contains(this.Transport))
        {
            throw new ArgumentException("Unsupported Hawk banking transport.", nameof(Transport));
        }

        this.RouteId = Require(RouteId, nameof(RouteId), 256);
        this.AuthenticationMode = Require(
            AuthenticationMode,
            nameof(AuthenticationMode),
            64);
        this.DirectBypass = DirectBypass;
        this.FunctionManifestId = Optional(FunctionManifestId, nameof(FunctionManifestId), 256);
        this.McpServerId = Optional(McpServerId, nameof(McpServerId), 128);
        this.McpToolName = Optional(McpToolName, nameof(McpToolName), 128);
        this.McpToolVersion = Optional(McpToolVersion, nameof(McpToolVersion), 64);
        this.McpToolFingerprintId = Optional(
            McpToolFingerprintId,
            nameof(McpToolFingerprintId),
            128);
        this.ToolboxId = Optional(ToolboxId, nameof(ToolboxId), 128);
        this.ToolboxVersion = Optional(ToolboxVersion, nameof(ToolboxVersion), 64);
        this.ProjectConnectionId = Optional(
            ProjectConnectionId,
            nameof(ProjectConnectionId),
            256);
        this.HttpMethod = Optional(HttpMethod, nameof(HttpMethod), 16)?.ToUpperInvariant();
        this.RouteTemplate = Optional(RouteTemplate, nameof(RouteTemplate), 512);
        this.OpenapiOperationId = Optional(
            OpenapiOperationId,
            nameof(OpenapiOperationId),
            256);
        this.OpenapiDocumentFingerprint = OptionalSha256(
            OpenapiDocumentFingerprint,
            nameof(OpenapiDocumentFingerprint));
        this.ApimApiId = Optional(ApimApiId, nameof(ApimApiId), 256);
        this.ApimRevision = Optional(ApimRevision, nameof(ApimRevision), 64);
        this.ApimBackendId = Optional(ApimBackendId, nameof(ApimBackendId), 256);
        ValidateRequiredMaterial();
    }

    /// <summary>Function, MCP, Toolbox, REST, OpenAPI, or APIM.</summary>
    public string Transport { get; }
    /// <summary>Stable route identifier selected by trusted application configuration.</summary>
    public string RouteId { get; }
    /// <summary>Actual transport authentication mode.</summary>
    public string AuthenticationMode { get; }
    /// <summary>Whether the route explicitly bypasses the managed Hawk boundary.</summary>
    public bool DirectBypass { get; }
    /// <summary>Promoted function manifest identifier.</summary>
    public string? FunctionManifestId { get; }
    /// <summary>Existing Hawk MCP server identifier.</summary>
    public string? McpServerId { get; }
    /// <summary>Exact MCP tool name.</summary>
    public string? McpToolName { get; }
    /// <summary>Exact MCP tool version.</summary>
    public string? McpToolVersion { get; }
    /// <summary>Existing Hawk ToolFingerprint identifier.</summary>
    public string? McpToolFingerprintId { get; }
    /// <summary>Foundry Toolbox identifier.</summary>
    public string? ToolboxId { get; }
    /// <summary>Promoted Toolbox version.</summary>
    public string? ToolboxVersion { get; }
    /// <summary>Foundry project-connection identifier.</summary>
    public string? ProjectConnectionId { get; }
    /// <summary>Bound HTTP method.</summary>
    public string? HttpMethod { get; }
    /// <summary>Bound route template without query material.</summary>
    public string? RouteTemplate { get; }
    /// <summary>OpenAPI operation identifier.</summary>
    public string? OpenapiOperationId { get; }
    /// <summary>Lowercase SHA-256 of the promoted OpenAPI document.</summary>
    public string? OpenapiDocumentFingerprint { get; }
    /// <summary>APIM API identifier.</summary>
    public string? ApimApiId { get; }
    /// <summary>APIM revision.</summary>
    public string? ApimRevision { get; }
    /// <summary>APIM backend identifier.</summary>
    public string? ApimBackendId { get; }

    private void ValidateRequiredMaterial()
    {
        string?[] required = Transport switch
        {
            "function" => [FunctionManifestId],
            "mcp" => [McpServerId, McpToolName, McpToolVersion, McpToolFingerprintId],
            "toolbox" =>
            [
                ToolboxId,
                ToolboxVersion,
                ProjectConnectionId,
                McpServerId,
                McpToolName,
                McpToolVersion,
                McpToolFingerprintId,
            ],
            "rest" => [HttpMethod, RouteTemplate],
            "openapi" =>
            [
                HttpMethod,
                RouteTemplate,
                OpenapiOperationId,
                OpenapiDocumentFingerprint,
            ],
            "apim" =>
            [
                HttpMethod,
                RouteTemplate,
                OpenapiOperationId,
                OpenapiDocumentFingerprint,
                ApimApiId,
                ApimRevision,
                ApimBackendId,
            ],
            _ => throw new InvalidOperationException("Unsupported Hawk transport state."),
        };
        if (required.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException($"{Transport} transport binding is incomplete.");
        }
    }

    private static string Require(string? value, string parameterName, int maximum)
    {
        string normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length == 0 || normalized.Length > maximum)
        {
            throw new ArgumentException("A bounded non-empty value is required.", parameterName);
        }

        return normalized;
    }

    private static string? Optional(string? value, string parameterName, int maximum)
    {
        if (value is null)
        {
            return null;
        }

        return Require(value, parameterName, maximum);
    }

    private static string? OptionalSha256(string? value, string parameterName)
    {
        string? normalized = Optional(value, parameterName, 64);
        if (normalized is null)
        {
            return null;
        }

        if (normalized.Length != 64 || normalized.Any(character =>
                !char.IsAsciiHexDigit(character) || char.IsUpper(character)))
        {
            throw new ArgumentException(
                "A lowercase SHA-256 value is required.",
                parameterName);
        }

        return normalized;
    }
}

/// <summary>Factories for exact supported Hawk banking transport bindings.</summary>
public static class HawkTransportBindings
{
    /// <summary>Creates an in-process function binding.</summary>
    public static HawkTransportBinding Function(
        string routeId,
        string authenticationMode,
        string functionManifestId,
        bool directBypass = false) => new(
            "function",
            routeId,
            authenticationMode,
            directBypass,
            FunctionManifestId: functionManifestId);

    /// <summary>Creates an MCP binding referencing Hawk's existing tool inventory.</summary>
    public static HawkTransportBinding Mcp(
        string routeId,
        string authenticationMode,
        string serverId,
        string toolName,
        string toolVersion,
        string toolFingerprintId,
        bool directBypass = false) => new(
            "mcp",
            routeId,
            authenticationMode,
            directBypass,
            McpServerId: serverId,
            McpToolName: toolName,
            McpToolVersion: toolVersion,
            McpToolFingerprintId: toolFingerprintId);

    /// <summary>Creates a Foundry Toolbox binding over an existing MCP inventory item.</summary>
    public static HawkTransportBinding Toolbox(
        string routeId,
        string authenticationMode,
        string toolboxId,
        string toolboxVersion,
        string projectConnectionId,
        string serverId,
        string toolName,
        string toolVersion,
        string toolFingerprintId,
        bool directBypass = false) => new(
            "toolbox",
            routeId,
            authenticationMode,
            directBypass,
            McpServerId: serverId,
            McpToolName: toolName,
            McpToolVersion: toolVersion,
            McpToolFingerprintId: toolFingerprintId,
            ToolboxId: toolboxId,
            ToolboxVersion: toolboxVersion,
            ProjectConnectionId: projectConnectionId);

    /// <summary>Creates a direct REST binding.</summary>
    public static HawkTransportBinding Rest(
        string routeId,
        string authenticationMode,
        string httpMethod,
        string routeTemplate,
        bool directBypass = false) => new(
            "rest",
            routeId,
            authenticationMode,
            directBypass,
            HttpMethod: httpMethod,
            RouteTemplate: routeTemplate);

    /// <summary>Creates an OpenAPI operation binding.</summary>
    public static HawkTransportBinding OpenApi(
        string routeId,
        string authenticationMode,
        string httpMethod,
        string routeTemplate,
        string operationId,
        string documentFingerprint,
        bool directBypass = false) => new(
            "openapi",
            routeId,
            authenticationMode,
            directBypass,
            HttpMethod: httpMethod,
            RouteTemplate: routeTemplate,
            OpenapiOperationId: operationId,
            OpenapiDocumentFingerprint: documentFingerprint);

    /// <summary>Creates an APIM route, revision, backend, and OpenAPI binding.</summary>
    public static HawkTransportBinding Apim(
        string routeId,
        string authenticationMode,
        string httpMethod,
        string routeTemplate,
        string operationId,
        string documentFingerprint,
        string apiId,
        string revision,
        string backendId,
        bool directBypass = false) => new(
            "apim",
            routeId,
            authenticationMode,
            directBypass,
            HttpMethod: httpMethod,
            RouteTemplate: routeTemplate,
            OpenapiOperationId: operationId,
            OpenapiDocumentFingerprint: documentFingerprint,
            ApimApiId: apiId,
            ApimRevision: revision,
            ApimBackendId: backendId);
}

/// <summary>Attaches trusted route material to the existing immutable banking request.</summary>
public static class HawkBankingTransportAdapters
{
    /// <summary>Returns a new immutable request carrying the exact transport binding.</summary>
    public static BankingActionRequest Bind(
        BankingActionRequest source,
        HawkTransportBinding binding)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(binding);
        return new BankingActionRequest(
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
            source.Arguments,
            source.RequestedCustomerSubjectId,
            source.RequestedAccountId,
            source.RequestedResource,
            source.Destination,
            source.WorkloadIdentity,
            source.WorkloadIdentityType,
            source.WorkloadAuthenticationMode,
            source.WorkloadIdentitySource,
            source.WorkloadIdentityProvenance,
            source.SideEffectClass,
            source.PolicySnapshotId,
            binding);
    }
}
