# Rante Apps server SDK for .NET

Check, on your server, the access tokens your Rante app's frontend gets from
[`Rante.getAccessToken()`](https://github.com/rante-corporation/rante-apps-sdk/tree/main/packages/sdk), and find out
who and which tenant each request is for. Built on
[Microsoft.IdentityModel.JsonWebTokens](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet).
.NET 8 or later.

What a token contains and what is checked: [docs/tokens.md](https://github.com/rante-corporation/rante-apps-sdk/blob/main/docs/tokens.md).
The same checks, error codes and test cases exist for [Node.js](https://github.com/rante-corporation/rante-apps-sdk-node),
[Python](https://github.com/rante-corporation/rante-apps-sdk-python), [Java](https://github.com/rante-corporation/rante-apps-sdk-java),
[Go](https://github.com/rante-corporation/rante-apps-sdk-go) and [PHP](https://github.com/rante-corporation/rante-apps-sdk-php).

Status: 0.1.0. Rante's hosting of apps is being built to this design; tokens are issued once it is live.

## Install

Not published to NuGet yet: add the repository as a git submodule (or copy `src/Rante.Apps`) and reference the project.

```bash
git submodule add https://github.com/rante-corporation/rante-apps-sdk-dotnet external/rante-apps-sdk-dotnet
dotnet add reference external/rante-apps-sdk-dotnet/src/Rante.Apps/Rante.Apps.csproj
```

## Use

```csharp
using Rante.Apps;

// One verifier per app, as a singleton: it caches Rante Login's signing keys and is thread-safe.
builder.Services.AddSingleton(new RanteAppTokenVerifier(new RanteAppTokenVerifierOptions
{
    ClientId = builder.Configuration["RANTE_CLIENT_ID"]!,
}));

app.MapGet("/api/me", async (HttpContext context, RanteAppTokenVerifier verifier) =>
{
    try
    {
        var token = BearerToken.FromAuthorizationHeader(context.Request.Headers.Authorization.ToString()) ?? "";
        var principal = await verifier.VerifyAsync(token, context.RequestAborted);
        return Results.Json(new { principal.UserId, principal.TenantId, principal.Scopes });
    }
    catch (RanteAppsException error)
    {
        if (error.WwwAuthenticate is { } challenge) context.Response.Headers.WWWAuthenticate = challenge;
        return Results.Json(new { error = error.Code, message = error.Message }, statusCode: error.Status);
    }
});
```

Your pages should send `Content-Security-Policy: frame-ancestors https://portal.rante.com`
(`RanteApps.FrameAncestors`) so that only Rante can frame them.

## Options

| Property | Default | |
|---|---|---|
| `ClientId` | (required) | Your app's Application (client) ID. |
| `Tenants` | any tenant | Accept tokens of these tenants only (`tenant_not_allowed` otherwise). |
| `RequiredScopes` | none | Scopes every token must have (`insufficient_scope` otherwise). |
| `ExtraAudiences` | none | Audiences accepted besides the client ID, such as `api://{clientId}`. |
| `Authority` | `https://login.rante.com` | http is accepted for localhost only, for tests. |
| `ClockSkew` | 60 seconds | Clock difference tolerated for `exp`, `nbf` and `iat`. |
| `Algorithms` | `["RS256"]` | `RS256` and `ES256` are supported. |
| `Timeout` | 5 seconds | For each request to Rante Login. |
| `JwksCooldown` | 30 seconds | Minimum time between two key fetches (an unknown `kid` triggers one). |
| `JwksMaxAge` | 10 minutes | How long fetched keys are used before they are fetched again. |
| `HttpClient` | a shared client | For proxies or tests. |

## The principal

`RanteAppPrincipal` is a record: `UserId` (oid), `TenantId` (tid), `Subject` (sub: stable, different for every
app), `Name`, `Username` (preferred_username), `Email`, `AppId` (your client ID), `AuthorizedParty` (azp), `Scopes`
(from scp), `Roles`, `IssuedAt`, `ExpiresAt`, `Issuer` and `Claims` (every claim as a `JsonElement`).

## Errors

`VerifyAsync` throws `RanteAppsException` with `Code` one of `missing_token`, `invalid_token`, `token_expired` (401),
`tenant_not_allowed`, `insufficient_scope` (403), `discovery_failed`, `network_error` (503) or
`invalid_configuration` (500). `Status` is that HTTP status and `WwwAuthenticate` the header value to send with it
(or `null`).

## Example

[examples/AspNetCore](examples/AspNetCore) is a complete external app on ASP.NET Core minimal APIs: a page that asks
Rante for a token and an `/api/me` endpoint that checks it.

```bash
cd examples/AspNetCore
RANTE_CLIENT_ID=<your-app-id> dotnet run
```

Rante opens external apps from an `https://` address, so register the server behind one in
[manifest.json](examples/AspNetCore/manifest.json).

## Tests

```bash
dotnet test
```

`tests/Rante.Apps.Tests/conformance/tokens.json` is a copy of
[conformance/tokens.json](https://github.com/rante-corporation/rante-apps-sdk/blob/main/conformance/tokens.json): the
cases every server SDK passes. The tests sign them with keys generated for the run and answer the key requests in
process; nothing leaves the machine.

## License

[MIT](LICENSE). Report security problems privately through this repository's Security tab.
