using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Tokens;

namespace Rante.Apps.Tests;

/// <summary>
/// A stand-in for Rante Login's key publishing that answers in process (no network): the OpenID configuration and the
/// JWKS, with keys generated for the run, plus a signer that builds the tokens of conformance/tokens.json.
/// </summary>
public sealed class LocalLogin : HttpMessageHandler
{
    public const string Origin = "https://login.test";

    private readonly RSA _rsa1 = RSA.Create(2048);
    private readonly RSA _rsa2 = RSA.Create(2048);
    private readonly RSA _rsaOther = RSA.Create(2048);
    private readonly ECDsa _ec1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly List<Dictionary<string, string>> _published;

    public LocalLogin()
    {
        _published = [RsaJwk(_rsa1, "key-1"), EcJwk(_ec1, "ec-1")];
    }

    public int DiscoveryCount { get; private set; }

    public int JwksCount { get; private set; }

    /// <summary>When set, answers every request instead of the default behaviour.</summary>
    public Func<HttpRequestMessage, HttpResponseMessage>? Override { get; set; }

    public HttpClient Client() => new(this, disposeHandler: false);

    public void PublishSecondKey()
    {
        lock (_published)
        {
            _published.Add(RsaJwk(_rsa2, "key-2"));
        }
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (Override is not null)
        {
            return Task.FromResult(Override(request));
        }

        object body;
        switch (request.RequestUri!.AbsolutePath)
        {
            case "/common/v2.0/.well-known/openid-configuration":
                DiscoveryCount++;
                body = new Dictionary<string, string> { ["issuer"] = Origin + "/common/v2.0", ["jwks_uri"] = Origin + "/common/discovery/v2.0/keys" };
                break;
            case "/common/discovery/v2.0/keys":
                JwksCount++;
                lock (_published)
                {
                    body = new Dictionary<string, object> { ["keys"] = _published.ToArray() };
                }

                break;
            default:
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
        });
    }

    private static Dictionary<string, string> RsaJwk(RSA rsa, string kid)
    {
        var p = rsa.ExportParameters(false);
        return new() { ["kty"] = "RSA", ["n"] = Base64UrlEncoder.Encode(p.Modulus), ["e"] = Base64UrlEncoder.Encode(p.Exponent), ["kid"] = kid, ["alg"] = "RS256", ["use"] = "sig" };
    }

    private static Dictionary<string, string> EcJwk(ECDsa ec, string kid)
    {
        var p = ec.ExportParameters(false);
        return new() { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = Base64UrlEncoder.Encode(p.Q.X), ["y"] = Base64UrlEncoder.Encode(p.Q.Y), ["kid"] = kid, ["alg"] = "ES256", ["use"] = "sig" };
    }

    /// <summary>Signs exact JSON texts with key-1 (for payloads a JsonObject cannot express).</summary>
    public string SignRaw(string headerJson, string payloadJson)
    {
        var input = Base64UrlEncoder.Encode(headerJson) + "." + Base64UrlEncoder.Encode(payloadJson);
        return input + "." + Base64UrlEncoder.Encode(_rsa1.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    /// <summary>Signs header + claims. how: key-1 | key-2 | other-key | es256 | hs256-public-key | none.</summary>
    public string Token(JsonObject header, JsonObject claims, string how = "key-1")
    {
        var head = (JsonObject)header.DeepClone();
        switch (how)
        {
            case "es256":
                head["alg"] = "ES256";
                head["kid"] = "ec-1";
                break;
            case "hs256-public-key":
                head["alg"] = "HS256";
                break;
            case "none":
                head["alg"] = "none";
                break;
            case "key-2":
                head["kid"] = "key-2";
                break;
        }

        var input = Base64UrlEncoder.Encode(head.ToJsonString()) + "." + Base64UrlEncoder.Encode(claims.ToJsonString());
        var data = Encoding.ASCII.GetBytes(input);
        byte[] signature = how switch
        {
            "none" => [],
            "es256" => _ec1.SignData(data, HashAlgorithmName.SHA256),
            "hs256-public-key" => HMACSHA256.HashData(Encoding.ASCII.GetBytes(_rsa1.ExportSubjectPublicKeyInfoPem()), data),
            "other-key" => _rsaOther.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            "key-2" => _rsa2.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            _ => _rsa1.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
        };
        return input + "." + Base64UrlEncoder.Encode(signature);
    }
}

/// <summary>conformance/tokens.json, a copy of rante-apps-sdk/conformance/tokens.json.</summary>
public static class Cases
{
    public static readonly JsonObject Document = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "conformance", "tokens.json")))!;

    public static string ClientId => (string)Document["clientId"]!;

    public static string TenantId => (string)Document["tenantId"]!;

    public static string UserId => (string)Document["userId"]!;

    public static JsonObject Case(string name) =>
        (JsonObject)Document["cases"]!.AsArray().First(c => (string)c!["name"]! == name)!;

    /// <summary>Replaces the placeholders of conformance/tokens.json (see its description).</summary>
    public static JsonNode? Resolve(JsonNode? node, long now)
    {
        switch (node)
        {
            case JsonValue value when value.TryGetValue<string>(out var text):
                var m = Regex.Match(text, @"^\$now([+-]\d+)?$");
                if (m.Success)
                {
                    return JsonValue.Create(now + (m.Groups[1].Success ? long.Parse(m.Groups[1].Value) : 0));
                }

                return JsonValue.Create(text
                    .Replace("$iss", "$authority/$tenantId/v2.0")
                    .Replace("$authority", LocalLogin.Origin)
                    .Replace("$CLIENTID", ClientId.ToUpperInvariant())
                    .Replace("$clientId", ClientId)
                    .Replace("$TENANTID", TenantId.ToUpperInvariant())
                    .Replace("$otherTenantId", (string)Document["otherTenantId"]!)
                    .Replace("$tenantId", TenantId)
                    .Replace("$userId", UserId));
            case JsonArray array:
                return new JsonArray(array.Select(item => Resolve(item, now)).ToArray());
            case JsonObject obj:
                var result = new JsonObject();
                foreach (var (key, child) in obj)
                {
                    result[key] = Resolve(child, now);
                }

                return result;
            default:
                return node?.DeepClone();
        }
    }

    /// <summary>Builds the token of one conformance case.</summary>
    public static string BuildToken(JsonObject testCase, LocalLogin login, long now)
    {
        if (testCase["raw"] is JsonNode raw)
        {
            return (string)raw!;
        }

        var header = (JsonObject)Resolve(Document["header"], now)!;
        if (testCase["header"] is JsonObject extraHeader)
        {
            foreach (var (key, value) in (JsonObject)Resolve(extraHeader, now)!)
            {
                header[key] = value?.DeepClone();
            }
        }

        var claims = (JsonObject)Resolve(Document["claims"], now)!;
        if (testCase["claims"] is JsonObject changes)
        {
            foreach (var (key, value) in (JsonObject)Resolve(changes, now)!)
            {
                if (value is null)
                {
                    claims.Remove(key);
                }
                else
                {
                    claims[key] = value.DeepClone();
                }
            }
        }

        var token = login.Token(header, claims, (string?)testCase["sign"] ?? "key-1");
        if (testCase["tamper"] is JsonValue tamper && tamper.GetValue<bool>())
        {
            var parts = token.Split('.');
            var changed = (JsonObject)claims.DeepClone();
            changed["oid"] = "00000000-aaaa-bbbb-cccc-000000000000";
            parts[1] = Base64UrlEncoder.Encode(changed.ToJsonString());
            token = string.Join('.', parts);
        }

        return token;
    }
}
