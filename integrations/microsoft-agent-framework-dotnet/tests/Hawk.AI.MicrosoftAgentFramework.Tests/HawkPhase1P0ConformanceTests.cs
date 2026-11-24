using System.Reflection;
using Xunit;

namespace Hawk.AI.MicrosoftAgentFramework.Tests;

public sealed class HawkPhase1P0ConformanceTests
{
    public static TheoryData<Type> ImmutableAuthorityTypes => new()
    {
        typeof(AuthorizedResourceScope),
        typeof(SubjectExecutionContext),
        typeof(HawkAgentRunContext),
        typeof(HawkTransportBinding),
        typeof(StructuredBankingResultEnvelope),
        typeof(BankingResponseAssuranceMaterial),
    };

    [Theory]
    [MemberData(nameof(ImmutableAuthorityTypes))]
    public void AuthorityAndExecutionContractsExposeNoPublicMutation(Type contractType)
    {
        PropertyInfo[] mutableProperties = contractType
            .GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Where(property => property.SetMethod?.IsPublic is true)
            .ToArray();

        Assert.Empty(mutableProperties);
    }

    [Fact]
    public void SubjectContextContainsNoCredentialOrAssertionProperties()
    {
        string[] propertyNames = typeof(SubjectExecutionContext)
            .GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Select(property => property.Name)
            .ToArray();

        Assert.DoesNotContain(propertyNames, name =>
            name.Contains("Token", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("Secret", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("Credential", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("Assertion", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ModelFunctionAndResponseControlRemainSeparateContracts()
    {
        Assert.NotEqual(typeof(IHawkBankingControlClient), typeof(IHawkModelControlClient));
        Assert.NotEqual(typeof(IHawkBankingControlClient), typeof(IHawkResponseAssuranceClient));
        Assert.NotEqual(typeof(IHawkModelControlClient), typeof(IHawkResponseAssuranceClient));

        Assert.Contains(
            typeof(IHawkBankingControlClient).GetMethods(),
            method => method.Name == "AuthorizeAsync");
        Assert.Contains(
            typeof(IHawkModelControlClient).GetMethods(),
            method => method.Name == "AuthorizeModelRequestAsync");
        Assert.Contains(
            typeof(IHawkResponseAssuranceClient).GetMethods(),
            method => method.Name == "AssureStructuredResponseAsync");
    }

    [Fact]
    public void TransportFactoriesRepresentSixRoutesWithoutInferringHostedControl()
    {
        string[] factoryNames = typeof(HawkTransportBindings)
            .GetMethods(BindingFlags.Static | BindingFlags.Public)
            .Select(method => method.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            new[] { "Apim", "Function", "Mcp", "OpenApi", "Rest", "Toolbox" },
            factoryNames);
        Assert.DoesNotContain("HostedMcp", factoryNames);
        Assert.DoesNotContain("FoundryHostedAgent", factoryNames);
    }
}
