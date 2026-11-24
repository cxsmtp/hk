using Xunit;

namespace Hawk.AI.MicrosoftAgentFramework.Tests;

public sealed class HawkAgentRunContextTests
{
    [Fact]
    public void CreateDelegatedRun_AttenuatesAuthorityAndPreservesSubjectPurposeAndCorrelation()
    {
        SubjectExecutionContext subject = TestRunContexts.Subject();
        HawkAgentRunContext parent = TestRunContexts.Run(subject);

        HawkAgentRunContext child = parent.CreateDelegatedRun(
            childAgentId: "transaction-reader-agent",
            childRunId: "run-child-001",
            requestedAuthority: new[] { "account.read_summary" });

        Assert.Same(subject, child.Subject);
        Assert.Equal(parent.AiTransactionId, child.AiTransactionId);
        Assert.Equal(parent.ChainId, child.ChainId);
        Assert.Equal(parent.BusinessPurposeId, child.BusinessPurposeId);
        Assert.Equal(new[] { "bank-summary-agent", "transaction-reader-agent" }, child.AgentLineage);
        Assert.Equal(new[] { "account.read_summary" }, child.EffectiveAuthority);
        Assert.DoesNotContain("customer-001", child.ToString());
        Assert.DoesNotContain("acct-001", child.ToString());
    }

    [Fact]
    public void CreateDelegatedRun_RejectsAuthorityExpansion()
    {
        HawkAgentRunContext parent = TestRunContexts.Run(TestRunContexts.Subject());

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() =>
            parent.CreateDelegatedRun(
                childAgentId: "transfer-agent",
                childRunId: "run-child-002",
                requestedAuthority: new[]
                {
                    "account.read_summary",
                    "account.transfer",
                }));

        Assert.Equal("AUTHORITY_EXPANSION", error.Message);
    }

    [Fact]
    public void SubjectContext_RejectsUntrustedProvenanceAndOutlivingResourceScope()
    {
        DateTimeOffset now = DateTimeOffset.Parse("2026-08-14T10:00:00Z");
        AuthorizedResourceScope scope = TestRunContexts.ResourceScope(
            expiresAt: now.AddMinutes(6));

        Assert.Throws<ArgumentException>(() => TestRunContexts.Subject(
            provenance: "prompt"));
        Assert.Throws<ArgumentException>(() => TestRunContexts.Subject(
            expiresAt: now.AddMinutes(5),
            scopes: new[] { scope }));
    }

    [Fact]
    public void SubjectAndRunCollectionsAreDeepFrozen()
    {
        var operations = new List<string> { "read_summary" };
        var scopes = new List<AuthorizedResourceScope>
        {
            TestRunContexts.ResourceScope(operations: operations),
        };
        var authority = new List<string> { "account.read_summary" };
        SubjectExecutionContext subject = TestRunContexts.Subject(scopes: scopes);
        HawkAgentRunContext run = TestRunContexts.Run(subject, authority: authority);

        operations.Add("transfer");
        scopes.Clear();
        authority.Add("account.transfer");

        Assert.Equal(new[] { "read_summary" }, subject.ApprovedResourceScopes[0].AllowedOperations);
        Assert.Single(subject.ApprovedResourceScopes);
        Assert.Equal(new[] { "account.read_summary" }, run.EffectiveAuthority);
    }
}

internal static class TestRunContexts
{
    internal static AuthorizedResourceScope ResourceScope(
        DateTimeOffset? expiresAt = null,
        IReadOnlyList<string>? operations = null) => new(
            ResourceType: "account",
            ResourceReference: "acct-001",
            RelationshipToSubject: "owner",
            AllowedOperations: operations ?? new[] { "read_summary" },
            ExpiresAt: expiresAt ?? DateTimeOffset.Parse("2026-08-14T10:05:00Z"),
            SourceOfAuthority: "bank_api_gateway");

    internal static SubjectExecutionContext Subject(
        string provenance = "bank_api_gateway",
        DateTimeOffset? expiresAt = null,
        IReadOnlyList<AuthorizedResourceScope>? scopes = null) => new(
            TenantId: "tenant-001",
            SubjectType: "customer",
            SubjectId: "customer-001",
            AuthenticatedPrincipalId: "principal-001",
            SessionId: "mobile-session-001",
            Channel: "mobile_banking",
            DeviceTrustRef: "device-trust-001",
            ApprovedResourceScopes: scopes ?? new[] { ResourceScope() },
            ApprovedAccountIds: new[] { "acct-001" },
            PurposeId: "own-account-summary",
            AuthorityScope: new[] { "account.read_summary" },
            AuthTime: DateTimeOffset.Parse("2026-08-14T09:59:00Z"),
            IssuedAt: DateTimeOffset.Parse("2026-08-14T10:00:00Z"),
            ExpiresAt: expiresAt ?? DateTimeOffset.Parse("2026-08-14T10:05:00Z"),
            Nonce: "nonce-0000000001",
            Provenance: provenance,
            TrustLevel: "hardware_bound_session",
            SourceSystem: "bank-mobile-api",
            PolicyVersion: "bank-policy-v2");

    internal static HawkAgentRunContext Run(
        SubjectExecutionContext subject,
        IReadOnlyList<string>? authority = null) => new(
            Subject: subject,
            AiTransactionId: "transaction-001",
            RunId: "run-001",
            ChainId: "chain-001",
            AiSystemId: "foundry-bank-agent",
            AgentId: "bank-summary-agent",
            AgentLineage: new[] { "bank-summary-agent" },
            EffectiveAuthority: authority ?? new[] { "account.read_summary" },
            BusinessPurposeId: "own-account-summary",
            ConversationId: "conversation-001",
            ModelProvider: "azure_openai",
            ModelDeployment: "bank-gpt-4-1",
            ModelName: "gpt-4.1",
            Destination: "bank-foundry.internal",
            RequestClassification: "confidential",
            PolicySnapshotId: "bank-policy-v1");
}
