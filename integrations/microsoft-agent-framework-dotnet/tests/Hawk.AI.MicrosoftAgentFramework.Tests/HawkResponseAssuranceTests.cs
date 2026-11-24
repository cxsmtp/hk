using System.Text.Json;
using Xunit;

namespace Hawk.AI.MicrosoftAgentFramework.Tests;

public sealed class HawkResponseAssuranceTests
{
    [Fact]
    public async Task Allow_ReleasesOriginalStructuredClaims()
    {
        var client = new StubResponseAssuranceClient(Decision("allow"));
        var gate = new HawkStructuredResponseGate(client);

        HawkAssuredBankingResponse result = await gate.AssureAsync(
            Material(),
            regenerate: null,
            CancellationToken.None);

        Assert.True(result.Released);
        Assert.Equal("allow", result.Decision);
        Assert.Equal("AED", result.ResponseClaims?.GetProperty("currency").GetString());
        Assert.Equal(1, client.Calls);
    }

    [Fact]
    public async Task Block_ReleasesNothingAndNeverRegenerates()
    {
        var client = new StubResponseAssuranceClient(Decision("block"));
        var gate = new HawkStructuredResponseGate(client);
        var regenerationCalls = 0;

        HawkAssuredBankingResponse result = await gate.AssureAsync(
            Material(),
            (_, _) =>
            {
                regenerationCalls++;
                return ValueTask.FromResult<IReadOnlyDictionary<string, object?>>(Claims());
            },
            CancellationToken.None);

        Assert.False(result.Released);
        Assert.Null(result.ResponseClaims);
        Assert.Equal(0, regenerationCalls);
        Assert.Equal(1, client.Calls);
    }

    [Theory]
    [InlineData("redact")]
    [InlineData("safe_fallback")]
    public async Task ReplacementDecision_ReleasesOnlyHawkSafeResponse(string decision)
    {
        var safe = JsonSerializer.SerializeToElement(
            new Dictionary<string, object?> { ["currency"] = "AED" });
        var client = new StubResponseAssuranceClient(Decision(decision, safe));
        var gate = new HawkStructuredResponseGate(client);

        HawkAssuredBankingResponse result = await gate.AssureAsync(
            Material(),
            regenerate: null,
            CancellationToken.None);

        Assert.True(result.Released);
        Assert.Equal("AED", result.ResponseClaims?.GetProperty("currency").GetString());
        Assert.False(result.ResponseClaims?.TryGetProperty("total_amount", out _) ?? true);
    }

    [Fact]
    public async Task Regenerate_PerformsOneBoundedRetryAndValidatesReplacement()
    {
        var client = new StubResponseAssuranceClient(
            Decision("regenerate", shouldRegenerate: true),
            Decision("allow"));
        var gate = new HawkStructuredResponseGate(client);
        var regenerationCalls = 0;

        HawkAssuredBankingResponse result = await gate.AssureAsync(
            Material(),
            (_, _) =>
            {
                regenerationCalls++;
                return ValueTask.FromResult<IReadOnlyDictionary<string, object?>>(
                    new Dictionary<string, object?>
                    {
                        ["currency"] = "AED",
                        ["total_amount"] = "327.50",
                        ["transaction_count"] = 11,
                    });
            },
            CancellationToken.None);

        Assert.True(result.Released);
        Assert.Equal(1, regenerationCalls);
        Assert.Equal(2, client.Calls);
        Assert.Equal(new[] { 0, 1 }, client.Attempts);
    }

    [Fact]
    public async Task RepeatedRegenerate_FailsClosedAfterOneRetry()
    {
        var client = new StubResponseAssuranceClient(
            Decision("regenerate", shouldRegenerate: true),
            Decision("regenerate", shouldRegenerate: true));
        var gate = new HawkStructuredResponseGate(client);

        HawkAssuredBankingResponse result = await gate.AssureAsync(
            Material(),
            (_, _) => ValueTask.FromResult<IReadOnlyDictionary<string, object?>>(Claims()),
            CancellationToken.None);

        Assert.False(result.Released);
        Assert.Equal("block", result.Decision);
        Assert.Equal("BANKING_REGENERATION_LIMIT_EXCEEDED", result.ReasonCode);
        Assert.Equal(2, client.Calls);
    }

    [Fact]
    public void Material_FreezesClaimsAndRedactsStringFormatting()
    {
        var claims = Claims();
        BankingResponseAssuranceMaterial material = Material(claims);
        claims["total_amount"] = "999999.00";

        string serialized = JsonSerializer.Serialize(material);

        Assert.Contains("327.50", serialized);
        Assert.DoesNotContain("999999.00", serialized);
        Assert.DoesNotContain(material.AuthorizedCustomerFingerprint, material.ToString());
        Assert.DoesNotContain(material.AuthorizedAccountFingerprint, material.ToString());
    }

    private static Dictionary<string, object?> Claims() => new()
    {
        ["currency"] = "AED",
        ["total_amount"] = "327.50",
        ["transaction_count"] = 11,
    };

    private static BankingResponseAssuranceMaterial Material(
        IReadOnlyDictionary<string, object?>? candidate = null) => new(
            "11111111-1111-1111-1111-111111111111",
            "hmac-sha256:" + new string('1', 64),
            "hmac-sha256:" + new string('2', 64),
            new StructuredBankingResultEnvelope(
                "transaction-001",
                "action-001",
                "hmac-sha256:" + new string('1', 64),
                "hmac-sha256:" + new string('2', 64),
                new string('a', 64),
                "bank.account_summary",
                "1.0.0",
                new[] { "currency", "total_amount", "transaction_count" },
                new Dictionary<string, string>
                {
                    ["currency"] = "confidential",
                    ["total_amount"] = "confidential",
                    ["transaction_count"] = "confidential",
                },
                Claims(),
                new string('b', 64),
                "success"),
            candidate ?? Claims(),
            0,
            new HawkResponseEvidenceSource(
                "provider_reported",
                "foundry-function-result"));

    private static StructuredBankingResponseDecision Decision(
        string decision,
        JsonElement? safeResponse = null,
        bool shouldRegenerate = false) => new(
            decision,
            $"reason:{decision}",
            "limited_claim_check",
            "provider_reported",
            Array.Empty<string>(),
            Array.Empty<string>(),
            Array.Empty<string>(),
            safeResponse,
            shouldRegenerate,
            new string('b', 64),
            new string('c', 64),
            "11111111-1111-1111-1111-111111111111",
            "evidence-node-001",
            JsonSerializer.SerializeToElement(new { schema = "hawk.test" }));
}

internal sealed class StubResponseAssuranceClient(
    params StructuredBankingResponseDecision[] decisions) : IHawkResponseAssuranceClient
{
    private readonly Queue<StructuredBankingResponseDecision> _decisions = new(decisions);

    internal int Calls { get; private set; }
    internal List<int> Attempts { get; } = [];

    public Task<StructuredBankingResponseDecision> AssureStructuredResponseAsync(
        BankingResponseAssuranceMaterial material,
        CancellationToken cancellationToken)
    {
        Calls++;
        Attempts.Add(material.RegenerationAttempt);
        return Task.FromResult(_decisions.Dequeue());
    }
}
