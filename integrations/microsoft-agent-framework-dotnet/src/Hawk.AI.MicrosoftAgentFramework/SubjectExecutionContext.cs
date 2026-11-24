using System.Collections.ObjectModel;

namespace Hawk.AI.MicrosoftAgentFramework;

/// <summary>
/// One immutable resource boundary issued by an authoritative enterprise system.
/// Raw resource references are transient in-process authorization material and must not be logged.
/// </summary>
public sealed class AuthorizedResourceScope
{
    private static readonly HashSet<string> AuthoritativeProvenance = new(StringComparer.Ordinal)
    {
        "bank_api_gateway",
        "authenticated_mobile_backend",
        "verified_entra_claims",
        "verified_oidc_claims",
        "bank_identity_service",
        "trusted_session_broker",
    };

    /// <summary>Creates a deep-frozen resource scope.</summary>
    public AuthorizedResourceScope(
        string ResourceType,
        string ResourceReference,
        string RelationshipToSubject,
        IReadOnlyList<string> AllowedOperations,
        DateTimeOffset ExpiresAt,
        string SourceOfAuthority)
    {
        this.ResourceType = RequireText(ResourceType, nameof(ResourceType), 64);
        this.ResourceReference = RequireText(ResourceReference, nameof(ResourceReference), 512);
        this.RelationshipToSubject = RequireText(
            RelationshipToSubject,
            nameof(RelationshipToSubject),
            64);
        this.AllowedOperations = FreezeUnique(
            AllowedOperations,
            nameof(AllowedOperations),
            maximum: 100);
        this.ExpiresAt = ExpiresAt.ToUniversalTime();
        this.SourceOfAuthority = RequireText(
            SourceOfAuthority,
            nameof(SourceOfAuthority),
            64);
        if (!AuthoritativeProvenance.Contains(this.SourceOfAuthority))
        {
            throw new ArgumentException(
                "Resource scope requires authoritative provenance.",
                nameof(SourceOfAuthority));
        }
    }

    /// <summary>Canonical resource class.</summary>
    public string ResourceType { get; }
    /// <summary>Exact transient resource reference.</summary>
    public string ResourceReference { get; }
    /// <summary>Authoritative relationship between subject and resource.</summary>
    public string RelationshipToSubject { get; }
    /// <summary>Operations allowed within this scope.</summary>
    public IReadOnlyList<string> AllowedOperations { get; }
    /// <summary>Scope expiry.</summary>
    public DateTimeOffset ExpiresAt { get; }
    /// <summary>Authoritative system that issued the scope.</summary>
    public string SourceOfAuthority { get; }

    /// <summary>Never renders the raw resource reference.</summary>
    public override string ToString() =>
        $"AuthorizedResourceScope {{ ResourceType = {ResourceType}, " +
        $"Relationship = {RelationshipToSubject}, ResourceReference = [REDACTED] }}";

    internal static string RequireText(string value, string parameterName, int maximum)
    {
        string normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length == 0 || normalized.Length > maximum)
        {
            throw new ArgumentException(
                $"A bounded non-empty {parameterName} is required.",
                parameterName);
        }

        return normalized;
    }

    internal static IReadOnlyList<string> FreezeUnique(
        IReadOnlyList<string> values,
        string parameterName,
        int maximum)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count == 0 || values.Count > maximum)
        {
            throw new ArgumentException(
                $"{parameterName} must contain between 1 and {maximum} values.",
                parameterName);
        }

        string[] normalized = values
            .Select(value => RequireText(value, parameterName, 512))
            .ToArray();
        if (normalized.Distinct(StringComparer.Ordinal).Count() != normalized.Length)
        {
            throw new ArgumentException(
                $"{parameterName} values must be unique.",
                parameterName);
        }

        return Array.AsReadOnly(normalized);
    }
}

/// <summary>
/// Immutable subject authority propagated through one regulated AI transaction.
/// It deliberately contains no access token, refresh token, or subject assertion.
/// </summary>
public sealed class SubjectExecutionContext
{
    private static readonly HashSet<string> AuthoritativeProvenance = new(StringComparer.Ordinal)
    {
        "bank_api_gateway",
        "authenticated_mobile_backend",
        "verified_entra_claims",
        "verified_oidc_claims",
        "bank_identity_service",
        "trusted_session_broker",
    };

    /// <summary>Creates a validated, deep-frozen subject authority context.</summary>
    public SubjectExecutionContext(
        string TenantId,
        string SubjectType,
        string SubjectId,
        string AuthenticatedPrincipalId,
        string SessionId,
        string Channel,
        string DeviceTrustRef,
        IReadOnlyList<AuthorizedResourceScope> ApprovedResourceScopes,
        IReadOnlyList<string> ApprovedAccountIds,
        string PurposeId,
        IReadOnlyList<string> AuthorityScope,
        DateTimeOffset AuthTime,
        DateTimeOffset IssuedAt,
        DateTimeOffset ExpiresAt,
        string Nonce,
        string Provenance,
        string TrustLevel,
        string SourceSystem,
        string PolicyVersion)
    {
        this.TenantId = AuthorizedResourceScope.RequireText(TenantId, nameof(TenantId), 64);
        this.SubjectType = AuthorizedResourceScope.RequireText(
            SubjectType,
            nameof(SubjectType),
            64);
        this.SubjectId = AuthorizedResourceScope.RequireText(SubjectId, nameof(SubjectId), 256);
        this.AuthenticatedPrincipalId = AuthorizedResourceScope.RequireText(
            AuthenticatedPrincipalId,
            nameof(AuthenticatedPrincipalId),
            256);
        this.SessionId = AuthorizedResourceScope.RequireText(SessionId, nameof(SessionId), 128);
        this.Channel = AuthorizedResourceScope.RequireText(Channel, nameof(Channel), 64);
        this.DeviceTrustRef = AuthorizedResourceScope.RequireText(
            DeviceTrustRef,
            nameof(DeviceTrustRef),
            256);
        ArgumentNullException.ThrowIfNull(ApprovedResourceScopes);
        if (ApprovedResourceScopes.Count == 0 || ApprovedResourceScopes.Count > 100)
        {
            throw new ArgumentException(
                "ApprovedResourceScopes must contain between 1 and 100 values.",
                nameof(ApprovedResourceScopes));
        }

        this.ApprovedResourceScopes = Array.AsReadOnly(
            ApprovedResourceScopes.ToArray());
        this.ApprovedAccountIds = AuthorizedResourceScope.FreezeUnique(
            ApprovedAccountIds,
            nameof(ApprovedAccountIds),
            maximum: 100);
        this.PurposeId = AuthorizedResourceScope.RequireText(PurposeId, nameof(PurposeId), 128);
        this.AuthorityScope = AuthorizedResourceScope.FreezeUnique(
            AuthorityScope,
            nameof(AuthorityScope),
            maximum: 100);
        this.AuthTime = AuthTime.ToUniversalTime();
        this.IssuedAt = IssuedAt.ToUniversalTime();
        this.ExpiresAt = ExpiresAt.ToUniversalTime();
        this.Nonce = AuthorizedResourceScope.RequireText(Nonce, nameof(Nonce), 256);
        if (this.Nonce.Length < 16)
        {
            throw new ArgumentException("Nonce must contain at least 16 characters.", nameof(Nonce));
        }

        this.Provenance = AuthorizedResourceScope.RequireText(Provenance, nameof(Provenance), 64);
        if (!AuthoritativeProvenance.Contains(this.Provenance))
        {
            throw new ArgumentException(
                "Subject context requires authoritative provenance.",
                nameof(Provenance));
        }

        this.TrustLevel = AuthorizedResourceScope.RequireText(
            TrustLevel,
            nameof(TrustLevel),
            64);
        this.SourceSystem = AuthorizedResourceScope.RequireText(
            SourceSystem,
            nameof(SourceSystem),
            128);
        this.PolicyVersion = AuthorizedResourceScope.RequireText(
            PolicyVersion,
            nameof(PolicyVersion),
            128);
        if (this.AuthTime > this.IssuedAt || this.IssuedAt >= this.ExpiresAt)
        {
            throw new ArgumentException("Subject context time binding is invalid.");
        }

        if (this.ApprovedResourceScopes.Any(scope => scope.ExpiresAt > this.ExpiresAt))
        {
            throw new ArgumentException(
                "A resource scope cannot outlive the subject context.",
                nameof(ApprovedResourceScopes));
        }
    }

    /// <summary>Hawk tenant boundary.</summary>
    public string TenantId { get; }
    /// <summary>Subject class, such as customer.</summary>
    public string SubjectType { get; }
    /// <summary>Authoritative transient subject identifier.</summary>
    public string SubjectId { get; }
    /// <summary>Authenticated principal identifier.</summary>
    public string AuthenticatedPrincipalId { get; }
    /// <summary>Trusted originating session.</summary>
    public string SessionId { get; }
    /// <summary>Originating channel.</summary>
    public string Channel { get; }
    /// <summary>Trusted device/session evidence reference.</summary>
    public string DeviceTrustRef { get; }
    /// <summary>Explicit subject-resource scopes.</summary>
    public IReadOnlyList<AuthorizedResourceScope> ApprovedResourceScopes { get; }
    /// <summary>Legacy explicit approved accounts retained for transport compatibility.</summary>
    public IReadOnlyList<string> ApprovedAccountIds { get; }
    /// <summary>Authoritative Hawk Business Purpose.</summary>
    public string PurposeId { get; }
    /// <summary>Maximum authority available to this subject transaction.</summary>
    public IReadOnlyList<string> AuthorityScope { get; }
    /// <summary>Authentication timestamp.</summary>
    public DateTimeOffset AuthTime { get; }
    /// <summary>Context issue timestamp.</summary>
    public DateTimeOffset IssuedAt { get; }
    /// <summary>Context expiry timestamp.</summary>
    public DateTimeOffset ExpiresAt { get; }
    /// <summary>Replay-resistant context nonce.</summary>
    public string Nonce { get; }
    /// <summary>Authoritative identity provenance.</summary>
    public string Provenance { get; }
    /// <summary>Verified trust level.</summary>
    public string TrustLevel { get; }
    /// <summary>System that issued the context.</summary>
    public string SourceSystem { get; }
    /// <summary>Policy version bound to the context.</summary>
    public string PolicyVersion { get; }

    /// <summary>Never renders subject, principal, session, device, account, or nonce values.</summary>
    public override string ToString() =>
        $"SubjectExecutionContext {{ TenantId = {TenantId}, SubjectType = {SubjectType}, " +
        $"PurposeId = {PurposeId}, SensitiveMaterial = [REDACTED] }}";
}
