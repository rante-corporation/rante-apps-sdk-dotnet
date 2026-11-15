using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace Rante.Apps.Tests;

public sealed class VerifierTests
{
    private readonly LocalLogin _login = new();

    private RanteAppTokenVerifier Verifier(TimeSpan? cooldown = null, IReadOnlyList<string>? algorithms = null) => new(new RanteAppTokenVerifierOptions
    {
        ClientId = Cases.ClientId,
        Authority = LocalLogin.Origin,
        HttpClient = _login.Client(),
        JwksCooldown = cooldown ?? TimeSpan.FromSeconds(30),
        Algorithms = algorithms ?? ["RS256"],
    });

    private string ValidToken(JsonObject? claims = null, string? sign = null)
    {
        var testCase = new JsonObject();
        if (claims is not null)
        {
            testCase["claims"] = claims;
        }

        if (sign is not null)
        {
            testCase["sign"] = sign;
        }

        return Cases.BuildToken(testCase, _login, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    public static IEnumerable<object[]> BadOptions() =>
    [
        [new RanteAppTokenVerifierOptions { ClientId = "contoso-app" }],
        [new RanteAppTokenVerifierOptions { ClientId = Cases.ClientId, Authority = "http://login.example.com" }],
        [new RanteAppTokenVerifierOptions { ClientId = Cases.ClientId, Authority = "https://login.example.com/tenant" }],
        [new RanteAppTokenVerifierOptions { ClientId = Cases.ClientId, Algorithms = ["HS256"] }],
        [new RanteAppTokenVerifierOptions { ClientId = Cases.ClientId, Algorithms = [] }],
        [new RanteAppTokenVerifierOptions { ClientId = Cases.ClientId, Tenants = ["contoso"] }],
        [new RanteAppTokenVerifierOptions { ClientId = Cases.ClientId, ClockSkew = TimeSpan.FromSeconds(-1) }],
        [new RanteAppTokenVerifierOptions { ClientId = Cases.ClientId, RequiredScopes = ["two words"] }],
    ];

    [Theory]
    [MemberData(nameof(BadOptions))]
    public void TheOptionsAreChecked(RanteAppTokenVerifierOptions options)
    {
        var error = Assert.Throws<RanteAppsException>(() => new RanteAppTokenVerifier(options));
        Assert.Equal("invalid_configuration", error.Code);
    }

    [Fact]
    public void DefaultsAreNormalized()
    {
        Assert.Equal(Cases.ClientId, new RanteAppTokenVerifier(new RanteAppTokenVerifierOptions { ClientId = Cases.ClientId.ToUpperInvariant() }).ClientId);
        Assert.Equal("https://login.rante.com", new RanteAppTokenVerifier(new RanteAppTokenVerifierOptions { ClientId = Cases.ClientId }).Authority);
        Assert.Equal("http://localhost:8080", new RanteAppTokenVerifier(new RanteAppTokenVerifierOptions { ClientId = Cases.ClientId, Authority = "http://localhost:8080/" }).Authority);
        Assert.Equal("frame-ancestors https://portal.rante.com", RanteApps.FrameAncestors);
    }

    [Theory]
    [InlineData("Bearer abc.def.ghi", "abc.def.ghi")]
    [InlineData("bearer   abc.def-_~+/=", "abc.def-_~+/=")]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("Basic dXNlcjpwYXNz", null)]
    [InlineData("Bearer", null)]
    [InlineData("Bearer a b", null)]
    [InlineData("Bearer a,b", null)]
    public void BearerTokensAreRead(string? header, string? expected)
    {
        Assert.Equal(expected, BearerToken.FromAuthorizationHeader(header));
    }

    [Fact]
    public void ErrorsCarryStatusAndWwwAuthenticate()
    {
        Assert.Equal("Bearer", new RanteAppsException("missing_token", "x").WwwAuthenticate);
        Assert.Equal("Bearer error=\"invalid_token\", error_description=\"The 'token' expired.\"",
            new RanteAppsException("token_expired", "The \"token\" expired.").WwwAuthenticate);
        var scope = new RanteAppsException("insufficient_scope", "x", ["user.read", "auth.token"]);
        Assert.Equal(403, scope.Status);
        Assert.Equal("Bearer error=\"insufficient_scope\", scope=\"user.read auth.token\"", scope.WwwAuthenticate);
        Assert.Null(new RanteAppsException("tenant_not_allowed", "x").WwwAuthenticate);
        Assert.Equal(503, new RanteAppsException("network_error", "x").Status);
    }

    [Fact]
    public async Task TheConfigurationAndKeysAreFetchedOnce()
    {
        var verifier = Verifier();
        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => verifier.VerifyAsync(ValidToken())));
        await verifier.VerifyAsync(ValidToken());
        Assert.Equal(1, _login.DiscoveryCount);
        Assert.Equal(1, _login.JwksCount);
    }

    [Fact]
    public async Task AnUnknownKidDoesNotRefetchDuringTheCooldown()
    {
        var verifier = Verifier();
        await verifier.VerifyAsync(ValidToken());
        var header = new JsonObject { ["kid"] = "made-up" };
        for (var i = 0; i < 3; i++)
        {
            var token = Cases.BuildToken(new JsonObject { ["header"] = header.DeepClone() }, _login, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            await Assert.ThrowsAsync<RanteAppsException>(() => verifier.VerifyAsync(token));
        }

        Assert.Equal(1, _login.JwksCount);
    }

    [Fact]
    public async Task ANewKeyIsPickedUp()
    {
        var verifier = Verifier(cooldown: TimeSpan.Zero);
        await verifier.VerifyAsync(ValidToken());
        _login.PublishSecondKey();
        var principal = await verifier.VerifyAsync(ValidToken(sign: "key-2"));
        Assert.Equal(Cases.TenantId, principal.TenantId);
        Assert.Equal(2, _login.JwksCount);
    }

    [Fact]
    public async Task Es256IsAcceptedWhenAllowed()
    {
        var principal = await Verifier(algorithms: ["RS256", "ES256"]).VerifyAsync(ValidToken(sign: "es256"));
        Assert.Equal(Cases.UserId, principal.UserId);
    }

    [Fact]
    public async Task ThePrincipalCarriesTheClaims()
    {
        var principal = await Verifier().VerifyAsync(ValidToken(new JsonObject { ["roles"] = new JsonArray("Reader", 7), ["email"] = "ada@example.com" }));
        Assert.Equal(Cases.ClientId, principal.AppId);
        Assert.Equal("Reader", Assert.Single(principal.Roles));
        Assert.Equal("ada@example.com", principal.Email);
        Assert.True(principal.ExpiresAt > DateTimeOffset.UtcNow);
        Assert.Equal("2.0", principal.Claims["ver"].GetString());
    }

    [Fact]
    public async Task DiscoveryProblemsAreReported()
    {
        var token = ValidToken();
        _login.Override = _ => new HttpResponseMessage(HttpStatusCode.NotFound);
        Assert.Equal("discovery_failed", (await Assert.ThrowsAsync<RanteAppsException>(() => Verifier().VerifyAsync(token))).Code);

        _login.Override = _ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"issuer\":\"https://evil.example/common/v2.0\",\"jwks_uri\":\"https://evil.example/k\"}", Encoding.UTF8, "application/json"),
        };
        Assert.Equal("discovery_failed", (await Assert.ThrowsAsync<RanteAppsException>(() => Verifier().VerifyAsync(token))).Code);

        _login.Override = _ => throw new HttpRequestException("down");
        Assert.Equal("network_error", (await Assert.ThrowsAsync<RanteAppsException>(() => Verifier().VerifyAsync(token))).Code);
    }

    [Fact]
    public async Task AFailedFetchIsRetried()
    {
        var verifier = Verifier();
        _login.Override = _ => throw new HttpRequestException("down");
        Assert.Equal("network_error", (await Assert.ThrowsAsync<RanteAppsException>(() => verifier.VerifyAsync(ValidToken()))).Code);
        _login.Override = null;
        Assert.Equal(Cases.TenantId, (await verifier.VerifyAsync(ValidToken())).TenantId);
    }

    [Fact]
    public async Task RepeatedClaimsAreRefused()
    {
        // A correctly signed token whose payload names "aud" twice: JSON parsers disagree on which value wins.
        var claims = (JsonObject)Cases.Resolve(Cases.Document["claims"], DateTimeOffset.UtcNow.ToUnixTimeSeconds())!;
        var json = claims.ToJsonString();
        var doubled = json[..^1] + ",\"aud\":\"00000000-1111-2222-3333-444444444444\"}";
        var token = _login.SignRaw("{\"alg\":\"RS256\",\"kid\":\"key-1\",\"typ\":\"JWT\"}", doubled);
        var error = await Assert.ThrowsAsync<RanteAppsException>(() => Verifier().VerifyAsync(token));
        Assert.Equal("invalid_token", error.Code);
    }
}
