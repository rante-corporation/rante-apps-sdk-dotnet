using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Xunit;

namespace Rante.Apps.Packaging.Tests;

/// <summary>
/// Runs conformance/paths.json and conformance/manifests.json. CI checks the same files against the reference CLI
/// (tools/check-vectors.mjs), so the C# port and the JavaScript CLI apply the same rules.
/// </summary>
public sealed class VectorTests
{
    private static JsonObject Load(string name) =>
        (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "conformance", name)))!;

    /// <summary>{s*N} repeats s N times; {U+XXXX} is that character.</summary>
    private static string Expand(string value)
    {
        var withChars = Regex.Replace(value, @"\{U\+([0-9A-Fa-f]{4,6})\}", m => char.ConvertFromUtf32(Convert.ToInt32(m.Groups[1].Value, 16)));
        return Regex.Replace(withChars, @"\{([^*}]+)\*(\d+)\}", m => string.Concat(Enumerable.Repeat(m.Groups[1].Value, int.Parse(m.Groups[2].Value))));
    }

    private static JsonNode? Expand(JsonNode? node) => node switch
    {
        JsonValue v when v.TryGetValue<string>(out var s) => JsonValue.Create(Expand(s)),
        JsonArray a => new JsonArray(a.Select(Expand).ToArray()),
        JsonObject o => new JsonObject(o.Select(p => KeyValuePair.Create(p.Key, Expand(p.Value)))),
        _ => node?.DeepClone(),
    };

    public static IEnumerable<object[]> PathCases() =>
        Load("paths.json")["cases"]!.AsArray().Select(c => new object[] { c!.ToJsonString() });

    public static IEnumerable<object[]> ManifestCases() =>
        Load("manifests.json")["cases"]!.AsArray().Select(c => new object[] { (string)c!["name"]! });

    public static IEnumerable<object[]> RawCases() =>
        Load("manifests.json")["raw"]!.AsArray().Select(c => new object[] { (string)c!["name"]! });

    [Theory]
    [MemberData(nameof(PathCases))]
    public void PathVector(string json)
    {
        var c = JsonNode.Parse(json)!;
        var result = RantePackagePaths.Check(Expand((string)c["path"]!));
        Assert.Equal((string?)c["code"], result.IsValid ? null : result.Code);
        if (result.IsValid && c["normalized"] is JsonNode normalized)
        {
            Assert.Equal(Expand((string)normalized!), result.Path);
            Assert.Equal((bool)c["isDirectory"]!, result.IsDirectory);
        }
    }

    [Theory]
    [MemberData(nameof(ManifestCases))]
    public void ManifestVector(string name)
    {
        var doc = Load("manifests.json");
        var c = doc["cases"]!.AsArray().First(x => (string)x!["name"]! == name)!;
        JsonNode? manifest;
        if (c.AsObject().ContainsKey("manifest"))
        {
            manifest = Expand(c["manifest"]);
        }
        else
        {
            var baseManifest = (JsonObject)Expand(doc["base"]![(string)c["base"]!])!;
            if (c["set"] is JsonObject set)
            {
                foreach (var (key, value) in (JsonObject)Expand(set)!)
                {
                    if (value is null)
                    {
                        baseManifest.Remove(key);
                    }
                    else
                    {
                        baseManifest[key] = value.DeepClone();
                    }
                }
            }

            manifest = baseManifest;
        }

        using var document = JsonDocument.Parse(manifest?.ToJsonString() ?? "null");
        var fields = RanteManifest.Validate(document.RootElement).Select(e => e.Field ?? string.Empty).OrderBy(f => f, StringComparer.Ordinal).ToArray();
        var expected = c["fields"]!.AsArray().Select(f => (string)f!).OrderBy(f => f, StringComparer.Ordinal).ToArray();
        Assert.Equal(expected, fields);
    }

    [Theory]
    [MemberData(nameof(RawCases))]
    public void RawManifestVector(string name)
    {
        var doc = Load("manifests.json");
        var c = doc["raw"]!.AsArray().First(x => (string)x!["name"]! == name)!;
        byte[] bytes;
        if (c["hex"] is JsonNode hex)
        {
            bytes = Convert.FromHexString((string)hex!);
        }
        else if (c["bom"] is JsonNode bom)
        {
            bytes = [0xef, 0xbb, 0xbf, .. Encoding.UTF8.GetBytes(doc["base"]![(string)bom!]!.ToJsonString())];
        }
        else
        {
            bytes = Encoding.UTF8.GetBytes((string)c["text"]!);
        }

        var parsed = RanteManifest.Parse(bytes);
        Assert.Equal((string?)c["code"], parsed.Errors.Count > 0 ? parsed.Errors[0].Code : null);
        if (c["bom"] is not null)
        {
            Assert.Contains(parsed.Warnings, w => w.Code == "manifest_bom");
        }
    }
}
