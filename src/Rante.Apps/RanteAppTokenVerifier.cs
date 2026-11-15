using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Rante.Apps;

/// <summary>Constants of the Rante Apps server SDK.</summary>
public static class RanteApps
{
    /// <summary>The SDK version.</summary>
    public const string Version = "0.1.0";

    /// <summary>Rante Login, which issues app access tokens.</summary>
    public const string DefaultAuthority = "https://login.rante.com";

    /// <summary>The Content-Security-Policy directive an external app's pages send so that only Rante can frame them.</summary>
    public const string FrameAncestors = "frame-ancestors https://portal.rante.com";
}

/// <summary>Options of <see cref="RanteAppTokenVerifier"/>.</summary>
public sealed class RanteAppTokenVerifierOptions
{
    /// <summary>Your app's Application (client) ID.</summary>
    public required string ClientId { get; init; }

    /// <summary>Accept tokens of these tenants only.</summary>
    public IReadOnlyList<string>? Tenants { get; init; }

    /// <summary>Scopes every token must have (from its scp claim).</summary>
    public IReadOnlyList<string>? RequiredScopes { get; init; }

    /// <summary>Audiences accepted besides the client ID, such as api://{clientId}.</summary>
    public IReadOnlyList<string>? ExtraAudiences { get; init; }

    /// <summary>Default https://login.rante.com. http is accepted for localhost only, for tests.</summary>
    public string Authority { get; init; } = RanteApps.DefaultAuthority;

    /// <summary>Clock difference tolerated for exp, nbf and iat. Default 60 seconds, at most 10 minutes.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Default RS256. RS256 and ES256 are supported.</summary>
    public IReadOnlyList<string> Algorithms { get; init; } = ["RS256"];

    /// <summary>Timeout of each request to Rante Login. Default 5 seconds.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Minimum time between two key fetches (an unknown kid triggers one). Default 30 seconds.</summary>
    public TimeSpan JwksCooldown { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How long fetched keys are used before they are fetched again. Default 10 minutes.</summary>
    public TimeSpan JwksMaxAge { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>The HttpClient for Rante Login (for proxies or tests). A shared client is used when null.</summary>
    public HttpClient? HttpClient { get; init; }
}

/// <summary>Who a verified token is for.</summary>
public sealed record RanteAppPrincipal
{
    /// <summary>The person's object ID in the tenant (oid).</summary>
    public required string UserId { get; init; }

    /// <summary>The tenant (tid).</summary>
    public required string TenantId { get; init; }

    /// <summary>The person's subject for this app (sub): stable, different for every app.</summary>
    public string? Subject { get; init; }

    /// <summary>The display name (name).</summary>
    public string? Name { get; init; }

    /// <summary>preferred_username.</summary>
    public string? Username { get; init; }

    /// <summary>email.</summary>
    public string? Email { get; init; }

    /// <summary>Your client ID.</summary>
    public required string AppId { get; init; }

    /// <summary>azp: the client that asked for the token on the person's behalf.</summary>
    public string? AuthorizedParty { get; init; }

    /// <summary>The permissions the tenant granted (scp).</summary>
    public required IReadOnlyList<string> Scopes { get; init; }

    /// <summary>roles.</summary>
    public required IReadOnlyList<string> Roles { get; init; }

    /// <summary>iat.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>exp.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>iss.</summary>
    public required string Issuer { get; init; }

    /// <summary>Every claim of the token.</summary>
    public required IReadOnlyDictionary<string, JsonElement> Claims { get; init; }
}

/// <summary>Every failure, with a stable code (docs/tokens.md) and the HTTP status to answer with.</summary>
public sealed class RanteAppsException : Exception
{
    private static readonly Dictionary<string, int> Statuses = new(StringComparer.Ordinal)
    {
        ["missing_token"] = 401,
        ["invalid_token"] = 401,
        ["token_expired"] = 401,
        ["tenant_not_allowed"] = 403,
        ["insufficient_scope"] = 403,
        ["discovery_failed"] = 503,
        ["network_error"] = 503,
        ["invalid_configuration"] = 500,
    };

    /// <summary>Creates the exception.</summary>
    public RanteAppsException(string code, string message, IReadOnlyList<string>? requiredScopes = null, Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
        Status = Statuses.TryGetValue(code, out var status) ? status : 500;
        RequiredScopes = requiredScopes ?? [];
    }

    /// <summary>missing_token, invalid_token, token_expired, tenant_not_allowed, insufficient_scope, discovery_failed, network_error or invalid_configuration.</summary>
    public string Code { get; }

    /// <summary>The HTTP status to answer with.</summary>
    public int Status { get; }

    /// <summary>The scopes the verifier requires (for insufficient_scope).</summary>
    public IReadOnlyList<string> RequiredScopes { get; }

    /// <summary>The WWW-Authenticate header value for this error (RFC 6750), or null.</summary>
    public string? WwwAuthenticate => Code switch
    {
        "missing_token" => "Bearer",
        "invalid_token" or "token_expired" => $"Bearer error=\"invalid_token\", error_description=\"{HeaderText(Message)}\"",
        "insufficient_scope" => $"Bearer error=\"insufficient_scope\", scope=\"{HeaderText(string.Join(' ', RequiredScopes))}\"",
        _ => null,
    };

    private static string HeaderText(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            builder.Append(c is '"' or '\\' ? '\'' : c is < ' ' or > '~' ? ' ' : c);
        }

        return builder.ToString();
    }
}

/// <summary>Reads bearer tokens from Authorization headers.</summary>
public static partial class BearerToken
{
    [GeneratedRegex(@"^Bearer +([A-Za-z0-9\-._~+/]+=*)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Pattern();

    /// <summary>The token from an Authorization header value ("Bearer &lt;token&gt;"), or null when there is none.</summary>
    public static string? FromAuthorizationHeader(string? header)
    {
        if (header is null)
        {
            return null;
        }

        var match = Pattern().Match(header.Trim());
        return match.Success ? match.Groups[1].Value : null;
    }
}

/// <summary>
/// Checks Rante app access tokens for one app, as described in docs/tokens.md of github.com/rante-corporation/rante-apps-sdk.
/// Create one per app and reuse it (for example as a singleton): it caches Rante Login's signing keys. Thread-safe.
/// </summary>
public sealed partial class RanteAppTokenVerifier
{
    private static readonly HttpClient SharedHttpClient = new() { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
    private static readonly JsonWebTokenHandler Handler = new() { MapInboundClaims = false };
    private static readonly string[] SupportedAlgorithms = ["RS256", "ES256"];
    private static readonly string[] LocalHosts = ["localhost", "127.0.0.1", "[::1]", "::1"];

    private readonly string[] _audiences;
    private readonly HashSet<string>? _tenants;
    private readonly string[] _requiredScopes;
    private readonly TimeSpan _clockSkew;
    private readonly string[] _algorithms;
    private readonly TimeSpan _timeout;
    private readonly TimeSpan _jwksCooldown;
    private readonly TimeSpan _jwksMaxAge;
    private readonly HttpClient _http;
    private readonly SemaphoreSlim _refresh = new(1, 1);
    private volatile KeySnapshot? _snapshot;
    private string? _jwksUri;

    /// <summary>Creates a verifier. Throws <see cref="RanteAppsException"/> (invalid_configuration) for bad options.</summary>
    public RanteAppTokenVerifier(RanteAppTokenVerifierOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!IsGuid(options.ClientId))
        {
            throw Config("ClientId must be your app's Application (client) ID, a GUID.");
        }

        ClientId = options.ClientId.ToLowerInvariant();
        _audiences = [ClientId, .. CheckedList(options.ExtraAudiences, "ExtraAudiences", a => a.Length > 0).Select(a => a.ToLowerInvariant())];
        Authority = NormalizeAuthority(options.Authority);
        var tenants = CheckedList(options.Tenants, "Tenants", IsGuid).Select(t => t.ToLowerInvariant()).ToArray();
        _tenants = tenants.Length > 0 ? new HashSet<string>(tenants, StringComparer.Ordinal) : null;
        _requiredScopes = CheckedList(options.RequiredScopes, "RequiredScopes", s => s.Length > 0 && !s.Any(char.IsWhiteSpace)).ToArray();
        if (options.ClockSkew < TimeSpan.Zero || options.ClockSkew > TimeSpan.FromMinutes(10))
        {
            throw Config("ClockSkew must be between 0 and 10 minutes.");
        }

        _clockSkew = options.ClockSkew;
        _algorithms = options.Algorithms?.ToArray() ?? [];
        if (_algorithms.Length == 0 || _algorithms.Any(a => !SupportedAlgorithms.Contains(a, StringComparer.Ordinal)))
        {
            throw Config("Algorithms must be a non-empty subset of RS256, ES256.");
        }

        if (options.Timeout <= TimeSpan.Zero || options.JwksCooldown < TimeSpan.Zero || options.JwksMaxAge <= TimeSpan.Zero)
        {
            throw Config("Timeout and JwksMaxAge must be positive, JwksCooldown not negative.");
        }

        _timeout = options.Timeout;
        _jwksCooldown = options.JwksCooldown;
        _jwksMaxAge = options.JwksMaxAge;
        _http = options.HttpClient ?? SharedHttpClient;
    }

    /// <summary>Your client ID, in lower case.</summary>
    public string ClientId { get; }

    /// <summary>The authority, such as https://login.rante.com.</summary>
    public string Authority { get; }

    /// <summary>Verifies a raw JWT (without "Bearer ") and returns who it is for.</summary>
    /// <exception cref="RanteAppsException">The token is missing or refused, or Rante Login could not be reached.</exception>
    public async Task<RanteAppPrincipal> VerifyAsync(string? token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(token))
        {
            throw new RanteAppsException("missing_token", "No access token was sent.");
        }

        if (token.Length > 16384 || !JwtShape().IsMatch(token))
        {
            throw Invalid("The access token is not a JSON Web Token.");
        }

        string? alg;
        string? kid;
        try
        {
            using var header = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(token[..token.IndexOf('.')]));
            alg = StringProperty(header.RootElement, "alg");
            kid = StringProperty(header.RootElement, "kid");
        }
        catch (Exception e) when (e is JsonException or FormatException or ArgumentException or InvalidOperationException)
        {
            throw Invalid("The access token header cannot be read.", e);
        }

        if (alg is null || !_algorithms.Contains(alg, StringComparer.Ordinal))
        {
            throw Invalid($"The access token is signed with {alg ?? "no algorithm"}, which is not accepted.");
        }

        if (string.IsNullOrEmpty(kid))
        {
            throw Invalid("The access token names no signing key (kid).");
        }

        var key = await GetSigningKeyAsync(kid, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(key.Alg) && key.Alg != alg)
        {
            throw Invalid("The access token's algorithm does not match its signing key.");
        }

        var result = await Handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKey = key,
            ValidateIssuerSigningKey = false,
            ValidateIssuer = false,
            ValidateAudience = false,
            // exp, nbf and iat are checked below, with the same rules as every other Rante Apps SDK.
            ValidateLifetime = false,
            RequireExpirationTime = false,
            RequireSignedTokens = true,
            ClockSkew = _clockSkew,
            ValidAlgorithms = _algorithms,
        }).ConfigureAwait(false);
        if (!result.IsValid)
        {
            throw Map(result.Exception);
        }

        return Principal(token);
    }

    private RanteAppPrincipal Principal(string token)
    {
        var payloadSegment = token.Split('.')[1];
        using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(payloadSegment));
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw Invalid("The access token payload is not a JSON object.");
        }

        var claims = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!claims.TryAdd(property.Name, property.Value.Clone()))
            {
                throw Invalid($"The access token repeats the claim {property.Name}.");
            }
        }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var skew = _clockSkew.TotalSeconds;
        var exp = NumberProperty(root, "exp") ?? throw Invalid("The access token has no expiry (exp).");
        if (exp <= now - skew)
        {
            throw new RanteAppsException("token_expired", "The access token has expired.");
        }

        if (root.TryGetProperty("nbf", out _) && (NumberProperty(root, "nbf") is not { } nbf || nbf > now + skew))
        {
            throw Invalid("The access token is not valid yet (nbf).");
        }

        var tid = StringProperty(root, "tid");
        if (!IsGuid(tid))
        {
            throw Invalid("The access token names no valid tenant (tid).");
        }

        var tenantId = tid!.ToLowerInvariant();
        var issuer = $"{Authority}/{tenantId}/v2.0";
        var iss = StringProperty(root, "iss");
        if (iss is null || !string.Equals(iss, issuer, StringComparison.OrdinalIgnoreCase))
        {
            throw Invalid("The access token was not issued by Rante Login for its tenant (iss).");
        }

        if (!AudienceMatches(root))
        {
            throw Invalid("The access token was issued for another app (aud).");
        }

        var iat = NumberProperty(root, "iat");
        if (root.TryGetProperty("iat", out _) && (iat is null || iat > now + _clockSkew.TotalSeconds))
        {
            throw Invalid("The access token was issued in the future (iat).");
        }

        var oid = StringProperty(root, "oid");
        if (!IsGuid(oid))
        {
            throw Invalid("The access token names no person (oid).");
        }

        if (root.TryGetProperty("idtyp", out var idtyp) && !(idtyp.ValueKind == JsonValueKind.String && idtyp.GetString() == "user"))
        {
            throw Invalid("The access token is not a person's token (idtyp).");
        }

        if (_tenants is not null && !_tenants.Contains(tenantId))
        {
            throw new RanteAppsException("tenant_not_allowed", "This tenant may not use this app.");
        }

        var scp = StringProperty(root, "scp");
        string[] scopes = scp is null ? [] : scp.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var missing = _requiredScopes.Where(s => !scopes.Contains(s, StringComparer.Ordinal)).ToArray();
        if (missing.Length > 0)
        {
            throw new RanteAppsException(
                "insufficient_scope",
                $"The access token lacks the scope{(missing.Length > 1 ? "s" : string.Empty)} {string.Join(", ", missing)}.",
                _requiredScopes);
        }

        var roles = new List<string>();
        if (root.TryGetProperty("roles", out var rolesElement) && rolesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var role in rolesElement.EnumerateArray())
            {
                if (role.ValueKind == JsonValueKind.String)
                {
                    roles.Add(role.GetString()!);
                }
            }
        }

        return new RanteAppPrincipal
        {
            UserId = oid!.ToLowerInvariant(),
            TenantId = tenantId,
            Subject = StringProperty(root, "sub"),
            Name = StringProperty(root, "name"),
            Username = StringProperty(root, "preferred_username"),
            Email = StringProperty(root, "email"),
            AppId = ClientId,
            AuthorizedParty = StringProperty(root, "azp"),
            Scopes = scopes,
            Roles = roles,
            IssuedAt = iat is null ? null : DateTimeOffset.FromUnixTimeMilliseconds((long)(iat.Value * 1000)),
            ExpiresAt = DateTimeOffset.FromUnixTimeMilliseconds((long)(exp * 1000)),
            Issuer = iss,
            Claims = claims,
        };
    }

    private bool AudienceMatches(JsonElement root)
    {
        if (!root.TryGetProperty("aud", out var aud))
        {
            return false;
        }

        if (aud.ValueKind == JsonValueKind.String)
        {
            return _audiences.Contains(aud.GetString()!.ToLowerInvariant(), StringComparer.Ordinal);
        }

        return aud.ValueKind == JsonValueKind.Array && aud.EnumerateArray()
            .Any(a => a.ValueKind == JsonValueKind.String && _audiences.Contains(a.GetString()!.ToLowerInvariant(), StringComparer.Ordinal));
    }

    // ------------------------------------------------------------------------------------------- keys

    private sealed record KeySnapshot(Dictionary<string, JsonWebKey> Keys, DateTimeOffset FetchedAt);

    private async Task<JsonWebKey> GetSigningKeyAsync(string kid, CancellationToken cancellationToken)
    {
        var snapshot = _snapshot;
        if (snapshot is not null && DateTimeOffset.UtcNow - snapshot.FetchedAt <= _jwksMaxAge && snapshot.Keys.TryGetValue(kid, out var cached))
        {
            return cached;
        }

        await _refresh.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            snapshot = _snapshot;
            var now = DateTimeOffset.UtcNow;
            var stale = snapshot is null || now - snapshot.FetchedAt > _jwksMaxAge;
            if (stale || (!snapshot!.Keys.ContainsKey(kid) && now - snapshot.FetchedAt >= _jwksCooldown))
            {
                snapshot = await FetchKeysAsync(cancellationToken).ConfigureAwait(false);
                _snapshot = snapshot;
            }

            return snapshot.Keys.TryGetValue(kid, out var key)
                ? key
                : throw Invalid("No signing key of Rante Login matches the access token.");
        }
        finally
        {
            _refresh.Release();
        }
    }

    private async Task<KeySnapshot> FetchKeysAsync(CancellationToken cancellationToken)
    {
        if (_jwksUri is null)
        {
            var text = await GetStringAsync($"{Authority}/common/v2.0/.well-known/openid-configuration", "discovery_failed",
                "Rante Login's OpenID configuration", cancellationToken).ConfigureAwait(false);
            string? issuer;
            string? jwksUri;
            try
            {
                using var metadata = JsonDocument.Parse(text);
                issuer = StringProperty(metadata.RootElement, "issuer");
                jwksUri = StringProperty(metadata.RootElement, "jwks_uri");
            }
            catch (Exception e) when (e is JsonException or InvalidOperationException)
            {
                throw new RanteAppsException("discovery_failed", "Rante Login's OpenID configuration is not JSON.", null, e);
            }

            if (issuer != $"{Authority}/common/v2.0")
            {
                throw new RanteAppsException("discovery_failed", "Rante Login's OpenID configuration names another issuer.");
            }

            if (!Uri.TryCreate(jwksUri, UriKind.Absolute, out var uri) ||
                !(uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && LocalHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase))))
            {
                throw new RanteAppsException("discovery_failed", "Rante Login's OpenID configuration has no valid https jwks_uri.");
            }

            _jwksUri = jwksUri;
        }

        var json = await GetStringAsync(_jwksUri, "network_error", "Rante Login's signing keys", cancellationToken).ConfigureAwait(false);
        JsonWebKeySet set;
        try
        {
            set = new JsonWebKeySet(json);
        }
        catch (Exception e) when (e is ArgumentException or JsonException or InvalidOperationException)
        {
            throw new RanteAppsException("network_error", "Rante Login's signing keys are not a JSON Web Key Set.", null, e);
        }

        var keys = new Dictionary<string, JsonWebKey>(StringComparer.Ordinal);
        foreach (var key in set.Keys)
        {
            if (!string.IsNullOrEmpty(key.Kid) && (string.IsNullOrEmpty(key.Use) || key.Use == "sig"))
            {
                keys.TryAdd(key.Kid, key);
            }
        }

        return new KeySnapshot(keys, DateTimeOffset.UtcNow);
    }

    private async Task<string> GetStringAsync(string url, string failureCode, string what, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Accept.ParseAdd("application/json");
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new RanteAppsException(failureCode, $"{what} answered {(int)response.StatusCode}.");
            }

            return await response.Content.ReadAsStringAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException e) when (!cancellationToken.IsCancellationRequested)
        {
            throw new RanteAppsException("network_error", $"{what} could not be fetched in time.", null, e);
        }
        catch (HttpRequestException e)
        {
            throw new RanteAppsException("network_error", $"{what} could not be fetched.", null, e);
        }
    }

    // ------------------------------------------------------------------------------------------- helpers

    [GeneratedRegex(@"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex JwtShape();

    private static RanteAppsException Map(Exception? exception) => exception switch
    {
        SecurityTokenExpiredException => new RanteAppsException("token_expired", "The access token has expired.", null, exception),
        // SecurityTokenSignatureKeyNotFoundException derives from SecurityTokenInvalidSignatureException: it goes first.
        SecurityTokenSignatureKeyNotFoundException => Invalid("No signing key of Rante Login matches the access token.", exception),
        SecurityTokenInvalidSignatureException => Invalid("The access token signature is not valid.", exception),
        SecurityTokenNotYetValidException => Invalid("The access token is not valid yet (nbf).", exception),
        SecurityTokenNoExpirationException => Invalid("The access token has no expiry (exp).", exception),
        SecurityTokenInvalidAlgorithmException => Invalid("The access token's algorithm is not accepted.", exception),
        _ => Invalid($"The access token is not valid ({exception?.GetType().Name ?? "unknown"}).", exception),
    };

    private static RanteAppsException Invalid(string message, Exception? inner = null) => new("invalid_token", message, null, inner);

    private static RanteAppsException Config(string message) => new("invalid_configuration", message);

    private static bool IsGuid(string? value) => value is { Length: 36 } && Guid.TryParseExact(value, "D", out _);

    private static string? StringProperty(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static double? NumberProperty(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number ? value.GetDouble() : null;

    private static IEnumerable<string> CheckedList(IReadOnlyList<string>? values, string name, Func<string, bool> check)
    {
        if (values is null)
        {
            return [];
        }

        foreach (var value in values)
        {
            if (value is null || !check(value))
            {
                throw Config($"{name} has an invalid entry: \"{value}\".");
            }
        }

        return values;
    }

    private static string NormalizeAuthority(string? value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            throw Config("Authority must be an absolute URL such as https://login.rante.com.");
        }

        var local = LocalHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase);
        if (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && local))
        {
            throw Config("Authority must use https (http is accepted only for localhost, for tests).");
        }

        if (uri.AbsolutePath != "/" || uri.Query.Length > 0 || uri.Fragment.Length > 0 || uri.UserInfo.Length > 0)
        {
            throw Config("Authority is an origin only, such as https://login.rante.com.");
        }

        return uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
    }
}
