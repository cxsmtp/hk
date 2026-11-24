using System.Security.Cryptography;
using System.Text.Json;

namespace Hawk.AI.MicrosoftAgentFramework;

/// <summary>
/// Typed denial returned to an agent runtime without invoking the protected function.
/// </summary>
public sealed record HawkToolDeniedResult(
    string Decision,
    string ReasonCode,
    string ControlMode,
    string DecisionReceiptId,
    string? IntegrityResultId);

/// <summary>
/// Truthful result of Hawk's final function gate.
/// </summary>
public sealed record HawkFunctionResult(
    string Decision,
    string ReasonCode,
    string DecisionReceiptId,
    bool Executed,
    bool EvidenceComplete,
    string? Integrity,
    string? IntegrityResultId,
    string? ExecutionReceiptId,
    object? Output,
    HawkToolDeniedResult? Denial)
{
    /// <summary>Returns receipt/status metadata without formatting arbitrary tool output.</summary>
    public override string ToString() =>
        $"HawkFunctionResult {{ Decision = {Decision}, DecisionReceiptId = {DecisionReceiptId}, " +
        $"Executed = {Executed}, EvidenceComplete = {EvidenceComplete}, Output = [REDACTED] }}";
}

/// <summary>
/// Framework-independent final execution gate. It directly wraps the protected function delegate.
/// </summary>
public sealed class HawkFunctionExecutionGate
{
    private static readonly HashSet<string> ExecutableDecisions = new(StringComparer.Ordinal)
    {
        "allow",
        "warn",
    };

    private readonly IHawkBankingControlClient _hawk;

    /// <summary>Creates the final gate over a Hawk banking control client.</summary>
    public HawkFunctionExecutionGate(IHawkBankingControlClient hawk)
    {
        ArgumentNullException.ThrowIfNull(hawk);
        _hawk = hawk;
    }

    /// <summary>
    /// Authorizes preliminary material, re-reads final material immediately before execution,
    /// invokes <paramref name="next"/> at most once, and reports actual execution evidence.
    /// </summary>
    public async ValueTask<HawkFunctionResult> ExecuteAsync(
        BankingActionRequest preliminary,
        Func<BankingActionRequest> finalMaterial,
        Func<CancellationToken, ValueTask<object?>> next,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(preliminary);
        ArgumentNullException.ThrowIfNull(finalMaterial);
        ArgumentNullException.ThrowIfNull(next);

        string preliminaryHash = ComputeMaterialHash(preliminary);
        BankingAuthorization authorization = await _hawk
            .AuthorizeAsync(preliminary, cancellationToken)
            .ConfigureAwait(false);
        if (!ExecutableDecisions.Contains(authorization.Decision))
        {
            return Blocked(authorization, integrityResultId: null);
        }

        BankingActionRequest finalRequest = finalMaterial()
            ?? throw new InvalidOperationException("Final banking function material is unavailable.");
        string finalHash = ComputeMaterialHash(finalRequest);
        bool materialChanged = !CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(preliminaryHash),
            Convert.FromHexString(finalHash));
        string executionAttemptId = NewExecutionAttemptId();

        PreExecutionResult validation = await _hawk
            .ValidatePreExecutionAsync(
                authorization.DecisionReceiptId,
                executionAttemptId,
                finalRequest,
                cancellationToken)
            .ConfigureAwait(false);
        if (
            materialChanged
            || !validation.Executable
            || string.IsNullOrWhiteSpace(validation.ExecutionGrantId))
        {
            return DriftBlocked(authorization, validation);
        }

        object? output;
        try
        {
            output = await next(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await TryReportFailedExecutionAsync(
                    authorization,
                    validation.ExecutionGrantId,
                    executionAttemptId)
                .ConfigureAwait(false);
            throw;
        }
        catch (Exception)
        {
            await TryReportFailedExecutionAsync(
                    authorization,
                    validation.ExecutionGrantId,
                    executionAttemptId)
                .ConfigureAwait(false);
            throw;
        }

        try
        {
            ExecutionResult execution = await _hawk
                .ReportExecutionAsync(
                    authorization.DecisionReceiptId,
                    validation.ExecutionGrantId,
                    executionAttemptId,
                    "success",
                    cancellationToken)
                .ConfigureAwait(false);
            return new HawkFunctionResult(
                authorization.Decision,
                authorization.ReasonCode,
                authorization.DecisionReceiptId,
                Executed: true,
                EvidenceComplete: true,
                execution.Integrity,
                execution.IntegrityResultId,
                execution.ExecutionReceiptId,
                output,
                Denial: null);
        }
        catch (Exception)
        {
            return new HawkFunctionResult(
                authorization.Decision,
                authorization.ReasonCode,
                authorization.DecisionReceiptId,
                Executed: true,
                EvidenceComplete: false,
                Integrity: "evidence_unavailable",
                IntegrityResultId: null,
                ExecutionReceiptId: null,
                output,
                Denial: null);
        }
    }

    private static HawkFunctionResult Blocked(
        BankingAuthorization authorization,
        string? integrityResultId)
    {
        var denial = new HawkToolDeniedResult(
            authorization.Decision,
            authorization.ReasonCode,
            authorization.ControlMode,
            authorization.DecisionReceiptId,
            integrityResultId);
        return new HawkFunctionResult(
            authorization.Decision,
            authorization.ReasonCode,
            authorization.DecisionReceiptId,
            Executed: false,
            EvidenceComplete: true,
            Integrity: null,
            integrityResultId,
            ExecutionReceiptId: null,
            Output: null,
            denial);
    }

    private static HawkFunctionResult DriftBlocked(
        BankingAuthorization authorization,
        PreExecutionResult validation)
    {
        const string decision = "drift_result";
        const string reason = "banking_material_changed_after_authorization";
        var denial = new HawkToolDeniedResult(
            decision,
            reason,
            "inline_prevented",
            authorization.DecisionReceiptId,
            validation.IntegrityResultId);
        return new HawkFunctionResult(
            decision,
            reason,
            authorization.DecisionReceiptId,
            Executed: false,
            EvidenceComplete: validation.IntegrityResultId is not null,
            Integrity: "drift_detected",
            validation.IntegrityResultId,
            ExecutionReceiptId: null,
            Output: null,
            denial);
    }

    private async Task TryReportFailedExecutionAsync(
        BankingAuthorization authorization,
        string executionGrantId,
        string executionAttemptId)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await _hawk
                .ReportExecutionAsync(
                    authorization.DecisionReceiptId,
                    executionGrantId,
                    executionAttemptId,
                    "failure",
                    timeout.Token)
                .ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Execution already failed or was cancelled. Preserve the original exception.
        }
    }

    private static string NewExecutionAttemptId() => $"attempt:{Guid.NewGuid():N}";

    private static string ComputeMaterialHash(BankingActionRequest request)
    {
        using JsonDocument document = JsonSerializer.SerializeToDocument(
            request,
            BankingJson.Options);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            WriteCanonical(writer, document.RootElement);
        }

        return Convert.ToHexString(SHA256.HashData(stream.ToArray())).ToLowerInvariant();
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (JsonProperty property in element
                    .EnumerateObject()
                    .OrderBy(property => property.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteCanonical(writer, property.Value);
                }

                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (JsonElement item in element.EnumerateArray())
                {
                    WriteCanonical(writer, item);
                }

                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;
            case JsonValueKind.Number:
                writer.WriteRawValue(element.GetRawText(), skipInputValidation: true);
                break;
            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;
            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;
            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;
            default:
                throw new InvalidDataException(
                    $"Unsupported banking material JSON kind: {element.ValueKind}.");
        }
    }
}

internal static class BankingJson
{
    internal static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };
}
