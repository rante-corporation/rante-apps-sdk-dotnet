using System.Text.Json.Nodes;
using Xunit;

namespace Rante.Apps.Tests;

/// <summary>
/// Runs conformance/tokens.json (a copy of rante-apps-sdk/conformance/tokens.json): the cases every Rante Apps server
/// SDK passes, in every language.
/// </summary>
public sealed class ConformanceTests : IClassFixture<ConformanceTests.Fixture>
{
    private static readonly Dictionary<string, Func<RanteAppPrincipal, object?>> Fields = new()
    {
        ["userId"] = p => p.UserId,
        ["tenantId"] = p => p.TenantId,
        ["subject"] = p => p.Subject,
        ["name"] = p => p.Name,
        ["username"] = p => p.Username,
        ["authorizedParty"] = p => p.AuthorizedParty,
    };

    private readonly Fixture _fixture;

    public ConformanceTests(Fixture fixture)
    {
        _fixture = fixture;
    }

    public static IEnumerable<object[]> CaseNames() =>
        Cases.Document["cases"]!.AsArray().Select(c => new object[] { (string)c!["name"]! });

    [Theory]
    [MemberData(nameof(CaseNames))]
    public async Task Case(string name)
    {
        var testCase = Cases.Case(name);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var verifier = _fixture.Shared;
        if (testCase["options"] is JsonObject options)
        {
            var resolved = (JsonObject)Cases.Resolve(options, now)!;
            verifier = new RanteAppTokenVerifier(new RanteAppTokenVerifierOptions
            {
                ClientId = Cases.ClientId,
                Authority = LocalLogin.Origin,
                HttpClient = _fixture.Login.Client(),
                Tenants = resolved["tenants"]?.AsArray().Select(t => (string)t!).ToArray(),
                RequiredScopes = resolved["requiredScopes"]?.AsArray().Select(s => (string)s!).ToArray(),
            });
        }

        var token = Cases.BuildToken(testCase, _fixture.Login, now);
        var expect = (string?)testCase["expect"];
        if (expect is null)
        {
            var principal = await verifier.VerifyAsync(token);
            if (testCase["principal"] is JsonObject expected)
            {
                foreach (var (field, value) in (JsonObject)Cases.Resolve(expected, now)!)
                {
                    if (field == "scopes")
                    {
                        Assert.Equal(value!.AsArray().Select(s => (string)s!).ToArray(), principal.Scopes.ToArray());
                    }
                    else
                    {
                        Assert.Equal((string?)value, Fields[field](principal));
                    }
                }
            }
        }
        else
        {
            var error = await Assert.ThrowsAsync<RanteAppsException>(() => verifier.VerifyAsync(token));
            Assert.True(error.Code == expect, $"expected {expect}, got {error.Code}: {error.Message}");
        }
    }

    public sealed class Fixture
    {
        public Fixture()
        {
            Login = new LocalLogin();
            Shared = new RanteAppTokenVerifier(new RanteAppTokenVerifierOptions
            {
                ClientId = Cases.ClientId,
                Authority = LocalLogin.Origin,
                HttpClient = Login.Client(),
            });
        }

        public LocalLogin Login { get; }

        public RanteAppTokenVerifier Shared { get; }
    }
}
