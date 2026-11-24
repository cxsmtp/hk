using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace Hawk.AI.MicrosoftAgentFramework;

/// <summary>
/// Authenticated HTTP adapter for Hawk's banking authorization and existing receipt endpoints.
/// </summary>
public sealed class HawkBankingClient :
    IHawkBankingControlClient,
    IHawkModelControlClient,
    IHawkResponseAssuranceClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    private readonly HttpClient _httpClient;
    private readonly IHawkAccessTokenProvider _accessTokenProvider;
    private readonly string _tenantId;

    /// <summary>
    /// Creates a client that obtains a fresh access token for every Hawk request.
    /// </summary>
    public HawkBankingClient(
        HttpClient httpClient,
        IHawkAccessTokenProvider accessTokenProvider,
        string tenantId)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(accessTokenProvider);
        if (httpClient.BaseAddress is null || !httpClient.BaseAddress.IsAbsoluteUri)
        {
            throw new ArgumentException(
                "Hawk HttpClient must have an absolute BaseAddress.",
                nameof(httpClient));
        }

        if (string.IsNullOrWhiteSpace(tenantId))
        {
            throw new ArgumentException("Hawk tenant ID is required.", nameof(tenantId));
        }

        _httpClient = httpClient;
        _accessTokenProvider = accessTokenProvider;
        _tenantId = tenantId;
    }

    /// <inheritdoc />
    public Task<BankingAuthorization> AuthorizeAsync(
        BankingActionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return PostAsync<BankingActionRequest, BankingAuthorization>(
            "/runtime-control/banking-actions/authorize",
            request,
            cancellationToken);
    }

    /// <inheritdoc />
    public Task<PreExecutionResult> ValidatePreExecutionAsync(
        string decisionReceiptId,
        string executionAttemptId,
        BankingActionRequest finalAction,
        CancellationToken cancellationToken)
    {
        RequireIdentifier(decisionReceiptId, nameof(decisionReceiptId));
        RequireIdentifier(executionAttemptId, nameof(executionAttemptId));
        ArgumentNullException.ThrowIfNull(finalAction);
        return PostAsync<BankingPreExecutionRequest, PreExecutionResult>(
            "/runtime-control/banking-actions/pre-execution",
            new BankingPreExecutionRequest(
                decisionReceiptId,
                executionAttemptId,
                finalAction),
            cancellationToken);
    }

    /// <inheritdoc />
    public Task<ExecutionResult> ReportExecutionAsync(
        string decisionReceiptId,
        string executionGrantId,
        string executionAttemptId,
        string executionStatus,
        CancellationToken cancellationToken)
    {
        RequireIdentifier(decisionReceiptId, nameof(decisionReceiptId));
        RequireIdentifier(executionGrantId, nameof(executionGrantId));
        RequireIdentifier(executionAttemptId, nameof(executionAttemptId));
        RequireIdentifier(executionStatus, nameof(executionStatus));
        return PostAsync<BankingExecutionRequest, ExecutionResult>(
            "/runtime-control/banking-actions/execution",
            new BankingExecutionRequest(
                decisionReceiptId,
                executionGrantId,
                executionAttemptId,
                executionStatus),
            cancellationToken);
    }

    /// <inheritdoc />
    public Task<ModelAuthorization> AuthorizeModelRequestAsync(
        ModelRequestMaterial request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return PostAsync<ModelRequestMaterial, ModelAuthorization>(
            "/runtime-control/banking-models/authorize",
            request,
            cancellationToken);
    }

    /// <inheritdoc />
    public Task<ModelResponseValidation> ValidateModelResponseAsync(
        ModelResponseMaterial response,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);
        return PostAsync<ModelResponseMaterial, ModelResponseValidation>(
            "/runtime-control/banking-models/response",
            response,
            cancellationToken);
    }

    /// <inheritdoc />
    public Task<StructuredBankingResponseDecision> AssureStructuredResponseAsync(
        BankingResponseAssuranceMaterial material,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(material);
        return PostAsync<BankingResponseAssuranceMaterial, StructuredBankingResponseDecision>(
            "/runtime-control/banking-responses/assure",
            material,
            cancellationToken);
    }

    private async Task<TResponse> PostAsync<TRequest, TResponse>(
        string path,
        TRequest payload,
        CancellationToken cancellationToken)
    {
        string accessToken = await _accessTokenProvider
            .GetAccessTokenAsync(cancellationToken)
            .ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            throw new InvalidOperationException(
                "Hawk access token provider returned an empty token.");
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(payload, options: JsonOptions),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Add("X-Tenant-ID", _tenantId);

        using HttpResponseMessage response = await _httpClient
            .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        TResponse? result = await response.Content
            .ReadFromJsonAsync<TResponse>(JsonOptions, cancellationToken)
            .ConfigureAwait(false);
        if (result is null)
        {
            throw new InvalidDataException(
                "Hawk returned an empty banking control response.");
        }

        ValidateResponse(result);
        return result;
    }

    private static void ValidateResponse<TResponse>(TResponse response)
    {
        switch (response)
        {
            case BankingAuthorization authorization:
                RequireResponseIdentifier(
                    authorization.AiTransactionId,
                    "ai_transaction_id");
                RequireResponseIdentifier(authorization.ActionId, "action_id");
                RequireResponseIdentifier(authorization.ChainId, "chain_id");
                RequireResponseIdentifier(authorization.ReasonCode, "reason_code");
                RequireResponseIdentifier(authorization.ControlMode, "control_mode");
                RequireResponseIdentifier(
                    authorization.DecisionReceiptId,
                    "decision_receipt_id");
                if (authorization.Decision is not (
                    "allow" or "warn" or "block" or "require_approval"))
                {
                    throw new InvalidDataException(
                        "Hawk returned an invalid banking decision.");
                }

                if (authorization.CanonicalAction.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException(
                        "Hawk returned invalid canonical banking material.");
                }

                break;
            case PreExecutionResult gate:
                if (gate.Executable)
                {
                    RequireResponseIdentifier(
                        gate.ExecutionGrantId,
                        "execution_grant_id");
                    if (gate.GrantExpiresAt is null)
                    {
                        throw new InvalidDataException(
                            "Hawk returned an executable gate without an expiry.");
                    }
                }
                else if (gate.ExecutionGrantId is not null || gate.GrantExpiresAt is not null)
                {
                    throw new InvalidDataException(
                        "Hawk returned a grant for a blocked banking action.");
                }

                break;
            case ExecutionResult execution:
                RequireResponseIdentifier(
                    execution.ExecutionReceiptId,
                    "execution_receipt_id");
                RequireResponseIdentifier(
                    execution.IntegrityResultId,
                    "integrity_result_id");
                if (execution.Integrity is not ("matched" or "drift_detected"))
                {
                    throw new InvalidDataException(
                        "Hawk returned an invalid execution integrity result.");
                }

                if (execution.DriftFields is null)
                {
                    throw new InvalidDataException(
                        "Hawk returned execution integrity without drift fields.");
                }

                if (
                    (execution.Integrity == "matched" && execution.DriftFields.Count != 0)
                    || (execution.Integrity == "drift_detected" && execution.DriftFields.Count == 0)
                )
                {
                    throw new InvalidDataException(
                        "Hawk returned inconsistent execution integrity evidence.");
                }

                break;
            case ModelAuthorization model:
                RequireResponseIdentifier(model.AiTransactionId, "ai_transaction_id");
                RequireResponseIdentifier(model.ActionId, "action_id");
                RequireResponseIdentifier(model.ChainId, "chain_id");
                RequireResponseIdentifier(model.ReasonCode, "reason_code");
                RequireResponseIdentifier(model.ControlMode, "control_mode");
                RequireResponseIdentifier(model.DecisionReceiptId, "decision_receipt_id");
                if (model.Decision is not (
                    "allow" or "warn" or "block" or "require_approval"))
                {
                    throw new InvalidDataException(
                        "Hawk returned an invalid model authorization decision.");
                }

                break;
            case ModelResponseValidation modelResponse:
                RequireResponseIdentifier(modelResponse.ReasonCode, "reason_code");
                RequireResponseIdentifier(modelResponse.ControlMode, "control_mode");
                RequireResponseIdentifier(
                    modelResponse.DecisionReceiptId,
                    "decision_receipt_id");
                if (modelResponse.Decision is not (
                    "allow" or "redact" or "regenerate" or "safe_fallback" or "block"))
                {
                    throw new InvalidDataException(
                        "Hawk returned an invalid model response decision.");
                }

                if (
                    modelResponse.Decision is "redact" or "safe_fallback"
                    && string.IsNullOrWhiteSpace(modelResponse.SafeResponse))
                {
                    throw new InvalidDataException(
                        "Hawk returned a replacement decision without safe response material.");
                }

                break;
            case StructuredBankingResponseDecision assurance:
                RequireResponseIdentifier(assurance.Decision, "decision");
                RequireResponseIdentifier(assurance.ReasonCode, "reason_code");
                RequireResponseIdentifier(assurance.Assurance, "assurance");
                RequireResponseIdentifier(assurance.EvidenceGrade, "evidence_grade");
                RequireResponseIdentifier(
                    assurance.DecisionReceiptId,
                    "decision_receipt_id");
                RequireResponseIdentifier(assurance.EvidenceNodeId, "evidence_node_id");
                if (assurance.Decision is not (
                    "allow" or "redact" or "regenerate" or "safe_fallback" or "block"))
                {
                    throw new InvalidDataException(
                        "Hawk returned an invalid structured response decision.");
                }

                if (
                    assurance.Decision is "redact" or "safe_fallback"
                    && (
                        assurance.SafeResponse is null
                        || assurance.SafeResponse.Value.ValueKind != JsonValueKind.Object
                    ))
                {
                    throw new InvalidDataException(
                        "Hawk returned a structured replacement without safe response material.");
                }

                if (assurance.Evidence.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException(
                        "Hawk returned invalid structured response evidence.");
                }

                break;
        }
    }

    private static void RequireIdentifier(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("A non-empty identifier is required.", parameterName);
        }
    }

    private static void RequireResponseIdentifier(string? value, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException(
                $"Hawk returned a banking response without {fieldName}.");
        }
    }
}
