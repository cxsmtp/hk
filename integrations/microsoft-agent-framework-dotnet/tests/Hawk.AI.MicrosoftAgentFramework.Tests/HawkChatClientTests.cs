using Microsoft.Extensions.AI;
using System.Runtime.CompilerServices;
using Xunit;

namespace Hawk.AI.MicrosoftAgentFramework.Tests;

public sealed class HawkChatClientTests
{
    [Fact]
    public async Task GetResponseAsync_BlockedRequest_DoesNotInvokeProvider()
    {
        var provider = new StubChatClient("provider response");
        var hawk = new StubModelControlClient
        {
            Authorization = TestModelMaterial.Authorization("block"),
        };
        using var client = new HawkChatClient(
            provider,
            hawk,
            TestRunContexts.Run(TestRunContexts.Subject()),
            new StubModelMaterialFactory());

        HawkModelRequestDeniedException denial = await Assert.ThrowsAsync<HawkModelRequestDeniedException>(
            () => client.GetResponseAsync(
                new[] { new ChatMessage(ChatRole.User, "show my balance") },
                null,
                CancellationToken.None));

        Assert.Equal(0, provider.ResponseCalls);
        Assert.Equal("block", denial.Decision);
        Assert.Equal(new[] { "authorize_model" }, hawk.Calls);
    }

    [Fact]
    public async Task GetResponseAsync_AllowedRequestAndResponse_PreservesCorrelationAndReturnsProviderResponse()
    {
        var provider = new StubChatClient("AED 42.00");
        var hawk = new StubModelControlClient
        {
            Authorization = TestModelMaterial.Authorization("allow") with
            {
                StreamingCovered = true,
            },
        };
        var factory = new StubModelMaterialFactory();
        HawkAgentRunContext run = TestRunContexts.Run(TestRunContexts.Subject());
        using var client = new HawkChatClient(provider, hawk, run, factory);

        ChatResponse response = await client.GetResponseAsync(
            new[] { new ChatMessage(ChatRole.User, "show my balance") },
            null,
            CancellationToken.None);

        Assert.Equal("AED 42.00", response.Text);
        Assert.Equal(1, provider.ResponseCalls);
        Assert.Equal(new[] { "authorize_model", "validate_response" }, hawk.Calls);
        Assert.Equal(run.AiTransactionId, factory.LastRequest?.AiTransactionId);
        Assert.Equal(run.ChainId, factory.LastRequest?.ChainId);
        Assert.Equal(run.RunId, factory.LastRequest?.RunId);
        Assert.Equal("model-receipt-001", factory.LastAuthorization?.DecisionReceiptId);
    }

    [Fact]
    public async Task GetResponseAsync_BlockedResponse_DoesNotReturnProviderContent()
    {
        var provider = new StubChatClient("cross-customer secret");
        var hawk = new StubModelControlClient
        {
            ResponseValidation = TestModelMaterial.Response("block"),
        };
        using var client = new HawkChatClient(
            provider,
            hawk,
            TestRunContexts.Run(TestRunContexts.Subject()),
            new StubModelMaterialFactory());

        HawkModelResponseDeniedException denial = await Assert.ThrowsAsync<HawkModelResponseDeniedException>(
            () => client.GetResponseAsync(
                new[] { new ChatMessage(ChatRole.User, "show my balance") },
                null,
                CancellationToken.None));

        Assert.Equal(1, provider.ResponseCalls);
        Assert.DoesNotContain("cross-customer secret", denial.ToString());
        Assert.Equal("block", denial.Decision);
    }

    [Fact]
    public async Task GetResponseAsync_SafeFallback_ReplacesProviderContentDeterministically()
    {
        var provider = new StubChatClient("untrusted model prose");
        var hawk = new StubModelControlClient
        {
            ResponseValidation = TestModelMaterial.Response(
                "safe_fallback",
                "Your account summary is temporarily unavailable."),
        };
        using var client = new HawkChatClient(
            provider,
            hawk,
            TestRunContexts.Run(TestRunContexts.Subject()),
            new StubModelMaterialFactory());

        ChatResponse response = await client.GetResponseAsync(
            new[] { new ChatMessage(ChatRole.User, "show my balance") },
            null,
            CancellationToken.None);

        Assert.Equal("Your account summary is temporarily unavailable.", response.Text);
        Assert.DoesNotContain("untrusted model prose", response.Text);
    }

    [Fact]
    public async Task GetStreamingResponseAsync_DefaultModeFailsClosedBeforeProvider()
    {
        var provider = new StubChatClient("streamed secret");
        using var client = new HawkChatClient(
            provider,
            new StubModelControlClient(),
            TestRunContexts.Run(TestRunContexts.Subject()),
            new StubModelMaterialFactory());

        await Assert.ThrowsAsync<HawkStreamingNotCoveredException>(async () =>
        {
            await foreach (ChatResponseUpdate _ in client.GetStreamingResponseAsync(
                new[] { new ChatMessage(ChatRole.User, "stream my balance") },
                null,
                CancellationToken.None))
            {
            }
        });

        Assert.Equal(0, provider.StreamingCalls);
    }

    [Fact]
    public async Task GetStreamingResponseAsync_BufferedModeReleasesOnlyAfterResponseValidation()
    {
        var provider = new StubChatClient("buffered response");
        var hawk = new StubModelControlClient
        {
            Authorization = TestModelMaterial.Authorization("allow") with
            {
                StreamingCovered = true,
            },
        };
        using var client = new HawkChatClient(
            provider,
            hawk,
            TestRunContexts.Run(TestRunContexts.Subject()),
            new StubModelMaterialFactory(),
            HawkStreamingControlMode.BufferUntilValidated,
            maxBufferedCharacters: 1024);
        var updates = new List<ChatResponseUpdate>();

        await foreach (ChatResponseUpdate update in client.GetStreamingResponseAsync(
            new[] { new ChatMessage(ChatRole.User, "stream my balance") },
            null,
            CancellationToken.None))
        {
            Assert.Contains("validate_response", hawk.Calls);
            updates.Add(update);
        }

        Assert.Equal("buffered response", string.Concat(updates.Select(update => update.Text)));
        Assert.Equal(1, provider.StreamingCalls);
        Assert.Equal(new[] { "authorize_model", "validate_response" }, hawk.Calls);
    }

    [Fact]
    public async Task HashingMaterialFactory_UsesFreshAssertionAndStoresOnlyContentHashes()
    {
        var assertions = new StubSubjectAssertionProvider();
        var factory = new HawkHashingModelMaterialFactory(
            assertions,
            new StubClassificationProvider(),
            new HawkModelRuntimeIdentity(
                "foundry-managed-identity",
                "project_managed_identity",
                "managed_identity",
                "microsoft_entra",
                "verified_entra_claims"),
            actionIdFactory: () => "model-action-deterministic");
        HawkAgentRunContext run = TestRunContexts.Run(TestRunContexts.Subject());
        var messages = new[] { new ChatMessage(ChatRole.User, "raw customer prompt") };

        ModelRequestMaterial request = await factory.CreateRequestAsync(
            run,
            messages,
            null,
            streaming: false,
            CancellationToken.None);
        ModelResponseMaterial response = factory.CreateResponse(
            run,
            request,
            TestModelMaterial.Authorization("allow"),
            new ChatResponse(new ChatMessage(ChatRole.Assistant, "raw model response")),
            streaming: false);

        string requestJson = System.Text.Json.JsonSerializer.Serialize(request);
        string responseJson = System.Text.Json.JsonSerializer.Serialize(response);
        Assert.Equal(1, assertions.CallCount);
        Assert.Equal(64, request.RequestHash.Length);
        Assert.Equal(64, response.ResponseHash.Length);
        Assert.DoesNotContain("raw customer prompt", requestJson);
        Assert.DoesNotContain("raw model response", responseJson);
        Assert.DoesNotContain("raw customer prompt", request.ToString());
    }
}

internal sealed class StubSubjectAssertionProvider : IHawkSubjectAssertionProvider
{
    internal int CallCount { get; private set; }

    public ValueTask<string> GetSubjectAssertionAsync(CancellationToken cancellationToken)
    {
        CallCount++;
        return ValueTask.FromResult(
            "synthetic-signed-bank-assertion-that-is-long-enough");
    }
}

internal sealed class StubClassificationProvider : IHawkModelClassificationProvider
{
    public string ClassifyRequest(
        IReadOnlyList<ChatMessage> messages,
        ChatOptions? options) => "confidential";

    public string ClassifyResponse(ChatResponse response) => "confidential";
}

internal sealed class StubChatClient(string responseText) : IChatClient
{
    internal int ResponseCalls { get; private set; }
    internal int StreamingCalls { get; private set; }

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ResponseCalls++;
        return Task.FromResult(new ChatResponse(
            new ChatMessage(ChatRole.Assistant, responseText)));
    }

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        StreamingCalls++;
        await Task.Yield();
        yield return new ChatResponseUpdate(ChatRole.Assistant, responseText);
    }

    public object? GetService(Type serviceType, object? serviceKey = null) => null;

    public void Dispose()
    {
    }
}

internal sealed class StubModelControlClient : IHawkModelControlClient
{
    internal List<string> Calls { get; } = [];
    internal ModelAuthorization Authorization { get; init; } =
        TestModelMaterial.Authorization("allow");
    internal ModelResponseValidation ResponseValidation { get; init; } =
        TestModelMaterial.Response("allow");

    public Task<ModelAuthorization> AuthorizeModelRequestAsync(
        ModelRequestMaterial request,
        CancellationToken cancellationToken)
    {
        Calls.Add("authorize_model");
        return Task.FromResult(Authorization);
    }

    public Task<ModelResponseValidation> ValidateModelResponseAsync(
        ModelResponseMaterial response,
        CancellationToken cancellationToken)
    {
        Calls.Add("validate_response");
        return Task.FromResult(ResponseValidation);
    }
}

internal sealed class StubModelMaterialFactory : IHawkModelMaterialFactory
{
    internal ModelRequestMaterial? LastRequest { get; private set; }
    internal ModelAuthorization? LastAuthorization { get; private set; }

    public ValueTask<ModelRequestMaterial> CreateRequestAsync(
        HawkAgentRunContext run,
        IReadOnlyList<ChatMessage> messages,
        ChatOptions? options,
        bool streaming,
        CancellationToken cancellationToken)
    {
        LastRequest = TestModelMaterial.Request(run, streaming);
        return ValueTask.FromResult(LastRequest);
    }

    public ModelResponseMaterial CreateResponse(
        HawkAgentRunContext run,
        ModelRequestMaterial request,
        ModelAuthorization authorization,
        ChatResponse response,
        bool streaming)
    {
        LastAuthorization = authorization;
        return new ModelResponseMaterial(
            authorization.DecisionReceiptId,
            run.AiTransactionId,
            request.ActionId,
            run.ChainId,
            new string('c', 64),
            "confidential",
            streaming,
            "stop");
    }
}

internal static class TestModelMaterial
{
    internal static ModelRequestMaterial Request(
        HawkAgentRunContext run,
        bool streaming) => new(
            SubjectAssertion: "synthetic-signed-bank-assertion-that-is-long-enough",
            AiTransactionId: run.AiTransactionId,
            ActionId: "model-action-001",
            RunId: run.RunId,
            ChainId: run.ChainId,
            AiSystemId: run.AiSystemId,
            SourceAgentId: run.AgentId,
            DelegatedAgentIds: run.AgentLineage.Skip(1).ToArray(),
            Provider: run.ModelProvider,
            Deployment: run.ModelDeployment,
            Model: run.ModelName,
            RequestClassification: run.RequestClassification,
            SessionId: run.ConversationId,
            Streaming: streaming,
            Destination: run.Destination,
            RequestHash: new string('b', 64),
            WorkloadIdentity: "foundry-managed-identity",
            WorkloadIdentityType: "project_managed_identity",
            WorkloadAuthenticationMode: "managed_identity",
            WorkloadIdentitySource: "microsoft_entra",
            WorkloadIdentityProvenance: "verified_entra_claims",
            PolicySnapshotId: run.PolicySnapshotId);

    internal static ModelAuthorization Authorization(string decision) => new(
        AiTransactionId: "transaction-001",
        ActionId: "model-action-001",
        ChainId: "chain-001",
        Decision: decision,
        ReasonCode: decision == "allow" ? "bank_model_allowed" : "bank_model_binding_mismatch",
        ControlMode: decision == "allow" ? "inline_allowed" : "inline_prevented",
        DecisionReceiptId: "model-receipt-001",
        ModelBindingVerified: decision == "allow",
        StreamingCovered: false);

    internal static ModelResponseValidation Response(
        string decision,
        string? safeResponse = null) => new(
            Decision: decision,
            ReasonCode: $"bank_model_response_{decision}",
            ControlMode: decision == "allow" ? "inline_allowed" : "inline_prevented",
            SafeResponse: safeResponse,
            EvidenceComplete: true,
            DecisionReceiptId: "model-receipt-001");
}
