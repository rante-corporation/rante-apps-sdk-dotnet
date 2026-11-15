using System.Text;
using System.Text.Json.Nodes;

namespace Rante.Apps.Packaging.Tests;

/// <summary>Sample manifests and packages, the twins of rante-apps-sdk's packages/cli/test/helpers.js.</summary>
internal static class Samples
{
    public const string AppId = "3f2b8c1e-7d4a-4e9b-a6c5-1d2e3f4a5b6c";

    public const string AppJsLine = "console.log(\"hello from a Rante app\");\n";

    public const string DataJson = "{\"items\":[1,2,3]}";

    public static readonly byte[] Index = Encoding.UTF8.GetBytes("<!doctype html><title>x</title>");

    public static readonly byte[] Icon = Encoding.UTF8.GetBytes("<svg xmlns=\"http://www.w3.org/2000/svg\"/>");

    public static JsonObject Bundle(Action<JsonObject>? change = null)
    {
        var manifest = new JsonObject
        {
            ["manifestVersion"] = 1,
            ["id"] = AppId,
            ["name"] = "Hello Rante",
            ["version"] = "1.0.0",
            ["hosting"] = "bundle",
            ["entryPoint"] = "index.html",
            ["icon"] = "icon.svg",
            ["permissions"] = new JsonArray("user.read", "tenant.read"),
        };
        change?.Invoke(manifest);
        return manifest;
    }

    public static JsonObject External() => new()
    {
        ["manifestVersion"] = 1,
        ["id"] = AppId,
        ["name"] = "Contoso CRM",
        ["version"] = "2.3.0",
        ["hosting"] = "external",
        ["entryPoint"] = "https://crm.contoso.example/rante",
        ["icon"] = "https://crm.contoso.example/icon-128.png",
        ["permissions"] = new JsonArray("user.read", "tenant.read", "auth.token"),
    };

    public static byte[] Json(JsonNode node) => Encoding.UTF8.GetBytes(node.ToJsonString());

    /// <summary>manifest.json (the sample bundle), index.html and icon.svg, then <paramref name="extra"/>.</summary>
    public static byte[] ZipOf(params TestEntry[] extra) => ZipWith(Bundle(), extra);

    /// <summary>manifest.json, index.html and icon.svg, then <paramref name="extra"/>.</summary>
    public static byte[] ZipWith(JsonObject manifest, params TestEntry[] extra) => TestZip.Write(
    [
        new TestEntry("manifest.json", Json(manifest)),
        new TestEntry("index.html", Index),
        new TestEntry("icon.svg", Icon),
        .. extra,
    ]);

    /// <summary>The six-file sample app of rante-apps-sdk's tests, as a package.</summary>
    public static byte[] SampleApp() => TestZip.Write(
        new TestEntry("manifest.json", Json(Bundle())),
        new TestEntry("index.html", "<!doctype html><html><head><script src=\"app.js\"></script></head><body>Hello</body></html>\n"),
        new TestEntry("app.js", string.Concat(Enumerable.Repeat(AppJsLine, 20))),
        new TestEntry("styles.css", "body { font-family: system-ui; }\n"),
        new TestEntry("icon.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 16 16\"><rect width=\"16\" height=\"16\"/></svg>\n"),
        new TestEntry("assets/data.json", DataJson));
}

/// <summary>A new folder under the temp folder, deleted on dispose.</summary>
internal sealed class TempFolder : IDisposable
{
    public string Root { get; } = Directory.CreateTempSubdirectory("rante-packaging-tests-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
