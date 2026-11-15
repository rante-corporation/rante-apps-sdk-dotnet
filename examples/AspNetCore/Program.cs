// An external Rante app on ASP.NET Core: the page gets an access token from Rante and calls /api/me, which checks it
// with the Rante Apps server SDK.
//   RANTE_CLIENT_ID=<your app's client ID> dotnet run
using Rante.Apps;

var builder = WebApplication.CreateBuilder(args);
var clientId = builder.Configuration["RANTE_CLIENT_ID"]
    ?? throw new InvalidOperationException("Set RANTE_CLIENT_ID to your app's Application (client) ID.");
var tenants = builder.Configuration["RANTE_TENANTS"]?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

// One verifier for the whole process: it caches Rante Login's signing keys and is thread-safe.
builder.Services.AddSingleton(new RanteAppTokenVerifier(new RanteAppTokenVerifierOptions { ClientId = clientId, Tenants = tenants }));

var app = builder.Build();
var indexTemplate = await File.ReadAllTextAsync(Path.Combine(app.Environment.ContentRootPath, "content", "index.html"));

app.Use(async (context, next) =>
{
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    await next(context);
});

app.MapGet("/", (HttpContext context, RanteAppTokenVerifier verifier) =>
{
    // Only Rante may frame the app; everything else loads from this server.
    context.Response.Headers.ContentSecurityPolicy = $"{RanteApps.FrameAncestors}; default-src 'self'; object-src 'none'; base-uri 'none'";
    return Results.Content(indexTemplate.Replace("__RANTE_CLIENT_ID__", verifier.ClientId), "text/html; charset=utf-8");
});

app.UseStaticFiles(); // wwwroot: app.js, style.css, rante-sdk.js

app.MapGet("/api/me", async (HttpContext context, RanteAppTokenVerifier verifier) =>
{
    context.Response.Headers.CacheControl = "no-store";
    try
    {
        var token = BearerToken.FromAuthorizationHeader(context.Request.Headers.Authorization.ToString()) ?? string.Empty;
        var p = await verifier.VerifyAsync(token, context.RequestAborted);
        return Results.Json(new { p.UserId, p.TenantId, p.Name, p.Username, p.Scopes, p.ExpiresAt });
    }
    catch (RanteAppsException error)
    {
        if (error.WwwAuthenticate is { } challenge)
        {
            context.Response.Headers.WWWAuthenticate = challenge;
        }

        return Results.Json(new { error = error.Code, message = error.Message }, statusCode: error.Status);
    }
});

app.Logger.LogInformation("Rante opens external apps from an https address: put this server behind one and register it in manifest.json.");
app.Run();
