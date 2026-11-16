using System.Collections.Frozen;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Rante.Apps.Packaging;

/// <summary>A problem found in a package or a manifest, with a stable code (docs/package-format.md).</summary>
/// <param name="Code">The code, for example manifest_invalid or path_traversal.</param>
/// <param name="Message">A message for people.</param>
/// <param name="Path">The file the problem is about, when there is one.</param>
/// <param name="Field">The manifest field, for manifest_invalid.</param>
public sealed record RantePackageIssue(string Code, string Message, string? Path = null, string? Field = null);

/// <summary>The result of parsing manifest.json.</summary>
/// <param name="Manifest">The manifest, when it is a JSON document (also when it breaks manifest rules).</param>
/// <param name="Errors">Problems; empty when the manifest is valid.</param>
/// <param name="Warnings">Things that do not make the manifest invalid.</param>
public sealed record RanteManifestParse(JsonElement? Manifest, IReadOnlyList<RantePackageIssue> Errors, IReadOnlyList<RantePackageIssue> Warnings);

/// <summary>
/// manifest.json rules (docs/manifest.md), the C# twin of packages/cli/lib/manifest.js. JSON with repeated property
/// names is refused, so the manifest reads the same here and in the CLI.
/// </summary>
public static partial class RanteManifest
{
    /// <summary>The manifest format version this library knows.</summary>
    public const int ManifestVersion = 1;

    /// <summary>The permission scopes an app can request, with what each allows.</summary>
    public static readonly IReadOnlyDictionary<string, string> Scopes = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["user.read"] = "Read the signed-in person's ID and display name",
        ["user.email"] = "Read the signed-in person's email address",
        ["tenant.read"] = "Read the active tenant's ID and name",
        ["auth.token"] = "Get access tokens for the app's own API, issued by login.rante.com",
        ["notifications"] = "Show notifications in Rante",
        ["navigation"] = "Open Rante pages, and external links in a new tab",
        ["clipboard.write"] = "Write to the clipboard",
    }.ToFrozenDictionary(StringComparer.Ordinal);

    private static readonly string[] Fields =
        ["$schema", "manifestVersion", "id", "name", "version", "description", "author", "icon", "hosting", "entryPoint", "permissions", "connect"];

    private static readonly string[] AuthorFields = ["name", "email", "url"];
    private static readonly string[] IconExtensions = ["png", "svg", "jpg", "jpeg", "webp"];
    private static readonly string[] EntryExtensions = ["html", "htm"];
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    // Patterns end with \z, not $: in .NET, $ also matches before a final "\n", so "1.0.0\n" would pass.
    [GeneratedRegex(@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z", RegexOptions.CultureInvariant)]
    private static partial Regex GuidPattern();

    [GeneratedRegex(@"^0{8}-0{4}-0{4}-0{4}-0{12}\z", RegexOptions.CultureInvariant)]
    private static partial Regex EmptyGuid();

    // [0-9], never \d: .NET's \d matches every Unicode decimal digit, JavaScript's (the reference CLI) only 0-9.
    [GeneratedRegex(@"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?\z", RegexOptions.CultureInvariant)]
    private static partial Regex Semver();

    // Whitespace is checked by HasJsWhitespace (see IsEmail): .NET's \s is not JavaScript's \s.
    [GeneratedRegex(@"^[^@<>()"",;:\\\[\]]+@[^@<>()"",;:\\\[\]]+\.[^@<>()"",;:\\\[\]]+\z", RegexOptions.CultureInvariant)]
    private static partial Regex EmailShape();

    [GeneratedRegex(@"^(https|wss)://(\*\.)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)(?::([0-9]{1,5}))?\z", RegexOptions.CultureInvariant)]
    private static partial Regex ConnectSource();

    [GeneratedRegex(@"^https?:", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LooksLikeUrl();

    /// <summary>Parses manifest.json bytes strictly (UTF-8, no repeated property names) and validates it.</summary>
    public static RanteManifestParse Parse(ReadOnlySpan<byte> utf8)
    {
        var errors = new List<RantePackageIssue>();
        var warnings = new List<RantePackageIssue>();
        string text;
        try
        {
            text = StrictUtf8.GetString(utf8);
        }
        catch (DecoderFallbackException)
        {
            errors.Add(new RantePackageIssue("manifest_invalid_json", "manifest.json is not valid UTF-8.", "manifest.json"));
            return new RanteManifestParse(null, errors, warnings);
        }

        if (text.Length > 0 && text[0] == (char)0xFEFF)
        {
            text = text[1..];
            warnings.Add(new RantePackageIssue("manifest_bom", "manifest.json starts with a byte order mark; save it as UTF-8 without BOM.", "manifest.json"));
        }

        JsonElement manifest;
        try
        {
            using var document = JsonDocument.Parse(text, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64,
            });
            var repeated = FindRepeatedProperty(document.RootElement);
            if (repeated is not null)
            {
                errors.Add(new RantePackageIssue("manifest_invalid_json",
                    $"manifest.json is not valid JSON: Duplicate property \"{repeated}\".", "manifest.json"));
                return new RanteManifestParse(null, errors, warnings);
            }

            manifest = document.RootElement.Clone();
        }
        catch (JsonException e)
        {
            errors.Add(new RantePackageIssue("manifest_invalid_json", $"manifest.json is not valid JSON: {e.Message}", "manifest.json"));
            return new RanteManifestParse(null, errors, warnings);
        }

        foreach (var issue in Validate(manifest))
        {
            errors.Add(issue with { Path = "manifest.json" });
        }

        return new RanteManifestParse(manifest, errors, warnings);
    }

    private static string? FindRepeatedProperty(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject())
                {
                    if (!seen.Add(property.Name))
                    {
                        return property.Name;
                    }

                    if (FindRepeatedProperty(property.Value) is { } inner)
                    {
                        return inner;
                    }
                }

                return null;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    if (FindRepeatedProperty(item) is { } inner)
                    {
                        return inner;
                    }
                }

                return null;
            default:
                return null;
        }
    }

    /// <summary>Validates a parsed manifest. Returns an empty list when it is valid.</summary>
    public static IReadOnlyList<RantePackageIssue> Validate(JsonElement manifest)
    {
        var errors = new List<RantePackageIssue>();
        void Add(string field, string message) => errors.Add(new RantePackageIssue("manifest_invalid", message, null, field));

        if (manifest.ValueKind != JsonValueKind.Object)
        {
            Add(string.Empty, "manifest.json must contain a JSON object.");
            return errors;
        }

        foreach (var property in manifest.EnumerateObject())
        {
            if (!Fields.Contains(property.Name, StringComparer.Ordinal))
            {
                Add(property.Name, $"Unknown field \"{property.Name}\". Allowed fields: {string.Join(", ", Fields.Skip(1))}.");
            }
        }

        if (manifest.TryGetProperty("$schema", out var schema) && schema.ValueKind != JsonValueKind.String)
        {
            Add("$schema", "\"$schema\" must be a string.");
        }

        if (!(manifest.TryGetProperty("manifestVersion", out var version) && version.ValueKind == JsonValueKind.Number &&
              version.TryGetDouble(out var versionNumber) && versionNumber == ManifestVersion))
        {
            Add("manifestVersion", $"\"manifestVersion\" must be {ManifestVersion}.");
        }

        var id = StringOf(manifest, "id");
        if (id is null || !GuidPattern().IsMatch(id))
        {
            Add("id", "\"id\" must be your app's Application (client) ID, a GUID like 3f2b8c1e-7d4a-4e9b-a6c5-1d2e3f4a5b6c (Rante Portal > Developers > Apps).");
        }
        else if (EmptyGuid().IsMatch(id))
        {
            Add("id", "\"id\" is the empty GUID. Use your app's Application (client) ID.");
        }

        if (TextProblem(Get(manifest, "name"), "\"name\"", 60, required: true, trimmed: true) is { } nameProblem)
        {
            Add("name", nameProblem);
        }

        var semver = StringOf(manifest, "version");
        if (semver is null || semver.Length > 64 || !Semver().IsMatch(semver))
        {
            Add("version", "\"version\" must be a semantic version such as 1.0.0 or 2.1.0-beta.1.");
        }

        if (manifest.TryGetProperty("description", out var description) &&
            TextProblem(description, "\"description\"", 500, allowNewlines: true) is { } descriptionProblem)
        {
            Add("description", descriptionProblem);
        }

        if (manifest.TryGetProperty("author", out var author))
        {
            if (author.ValueKind != JsonValueKind.Object)
            {
                Add("author", "\"author\" must be an object with \"name\" and optionally \"email\" and \"url\".");
            }
            else
            {
                foreach (var property in author.EnumerateObject())
                {
                    if (!AuthorFields.Contains(property.Name, StringComparer.Ordinal))
                    {
                        Add($"author.{property.Name}", $"Unknown field \"author.{property.Name}\". Allowed: name, email, url.");
                    }
                }

                if (TextProblem(Get(author, "name"), "\"author.name\"", 100, required: true, trimmed: true) is { } authorName)
                {
                    Add("author.name", authorName);
                }

                if (author.TryGetProperty("email", out var email) &&
                    (email.ValueKind != JsonValueKind.String || email.GetString()!.Length > 254 || !IsEmail(email.GetString()!)))
                {
                    Add("author.email", "\"author.email\" must be an email address (no control or invisible formatting characters).");
                }

                if (author.TryGetProperty("url", out var url) && HttpsUrlProblem(url, "\"author.url\"") is { } urlProblem)
                {
                    Add("author.url", urlProblem);
                }
            }
        }

        var hosting = StringOf(manifest, "hosting");
        if (hosting is not ("bundle" or "external"))
        {
            Add("hosting", "\"hosting\" must be \"bundle\" (Rante hosts your files) or \"external\" (you host the app at an HTTPS URL).");
            hosting = null;
        }

        if (hosting == "bundle")
        {
            var entry = Get(manifest, "entryPoint");
            if (RelativeFileProblem(entry, "\"entryPoint\"", EntryExtensions) is { } entryProblem)
            {
                var hint = entry is { ValueKind: JsonValueKind.String } e && LooksLikeUrl().IsMatch(e.GetString()!)
                    ? " For an app on your own server, set \"hosting\" to \"external\"."
                    : string.Empty;
                Add("entryPoint", entryProblem + hint);
            }
        }
        else if (hosting == "external" && HttpsUrlProblem(Get(manifest, "entryPoint"), "\"entryPoint\"") is { } externalEntry)
        {
            Add("entryPoint", externalEntry);
        }

        if (manifest.TryGetProperty("icon", out var icon))
        {
            if (hosting == "external" && HttpsUrlProblem(icon, "\"icon\"") is { } externalIcon)
            {
                Add("icon", externalIcon);
            }
            else if (hosting == "bundle" && RelativeFileProblem(icon, "\"icon\"", IconExtensions) is { } bundleIcon)
            {
                Add("icon", bundleIcon);
            }
        }

        if (manifest.TryGetProperty("permissions", out var permissions))
        {
            if (permissions.ValueKind != JsonValueKind.Array)
            {
                Add("permissions", "\"permissions\" must be an array of scope names.");
            }
            else
            {
                var seen = new HashSet<string>(StringComparer.Ordinal);
                var index = 0;
                foreach (var scope in permissions.EnumerateArray())
                {
                    var name = scope.ValueKind == JsonValueKind.String ? scope.GetString()! : null;
                    if (name is null || !Scopes.ContainsKey(name))
                    {
                        Add($"permissions[{index}]", $"Unknown permission {scope.GetRawText()}. Known: {string.Join(", ", Scopes.Keys)}.");
                    }
                    else if (!seen.Add(name))
                    {
                        Add($"permissions[{index}]", $"\"{name}\" is listed twice.");
                    }

                    index++;
                }
            }
        }

        if (manifest.TryGetProperty("connect", out var connect))
        {
            if (hosting == "external")
            {
                Add("connect", "\"connect\" applies only to bundle apps. An external app sets its own Content-Security-Policy.");
            }
            else if (connect.ValueKind != JsonValueKind.Array)
            {
                Add("connect", "\"connect\" must be an array of origins such as \"https://api.example.com\".");
            }
            else if (connect.GetArrayLength() > 20)
            {
                Add("connect", $"\"connect\" lists {connect.GetArrayLength()} origins; the limit is 20.");
            }
            else
            {
                var seen = new HashSet<string>(StringComparer.Ordinal);
                var index = 0;
                foreach (var source in connect.EnumerateArray())
                {
                    var field = $"connect[{index++}]";
                    var text = source.ValueKind == JsonValueKind.String ? source.GetString()! : null;
                    var m = text is null ? null : ConnectSource().Match(text);
                    if (m is null || !m.Success)
                    {
                        Add(field, $"{source.GetRawText()} is not an origin. Use https://host or wss://host (lowercase, no path), optionally *.host for its subdomains.");
                        continue;
                    }

                    var host = m.Groups[3].Value;
                    if (m.Groups[2].Success && host.Split('.').Length < 2)
                    {
                        Add(field, $"{text} is too broad: a wildcard needs at least two labels after \"*.\".");
                    }

                    if (m.Groups[4].Success && int.Parse(m.Groups[4].Value, CultureInfo.InvariantCulture) is < 1 or > 65535)
                    {
                        Add(field, $"{text} has an invalid port.");
                    }

                    if (host == "localhost" || host.EndsWith(".localhost", StringComparison.Ordinal))
                    {
                        Add(field, $"{text} is a local host name.");
                    }

                    if (!seen.Add(text!))
                    {
                        Add(field, $"{text} is listed twice.");
                    }
                }
            }
        }

        return errors;
    }

    private static JsonElement? Get(JsonElement obj, string name) => obj.TryGetProperty(name, out var value) ? value : null;

    private static string? StringOf(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static bool HasControl(string value)
    {
        foreach (var c in value)
        {
            if (c <= 0x1f || (c >= 0x7f && c <= 0x9f))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Whether the text has a character that JavaScript's \s matches, as in the reference CLI. .NET's \s differs: it
    /// matches U+0085 and not U+FEFF.
    /// </summary>
    private static bool HasJsWhitespace(string value)
    {
        foreach (var c in value)
        {
            if (c is '\t' or '\n' or '\v' or '\f' or '\r' || c == 0x2028 || c == 0x2029 || c == 0xfeff ||
                char.GetUnicodeCategory(c) == UnicodeCategory.SpaceSeparator)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The reference CLI's email rule: no control or invisible formatting characters, no whitespace (as JavaScript
    /// sees it) and the shape local@domain.tld.
    /// </summary>
    private static bool IsEmail(string value) =>
        !HasControl(value) && !HasInvisible(value) && !HasJsWhitespace(value) && EmailShape().IsMatch(value);

    private static bool HasInvisible(string value)
    {
        foreach (var c in value)
        {
            if ((c >= 0x200b && c <= 0x200f) || (c >= 0x202a && c <= 0x202e) || (c >= 0x2060 && c <= 0x2064) ||
                (c >= 0x2066 && c <= 0x2069) || c == 0xfeff)
            {
                return true;
            }
        }

        return false;
    }

    private static string? TextProblem(JsonElement? value, string label, int max, bool required = false, bool trimmed = false, bool allowNewlines = false)
    {
        if (value is not { ValueKind: JsonValueKind.String } element)
        {
            return $"{label} must be a string.";
        }

        var text = element.GetString()!;
        if (required && text.Trim().Length == 0)
        {
            return $"{label} must not be empty.";
        }

        if (text.Length > max)
        {
            return $"{label} is {text.Length} characters long; the limit is {max}.";
        }

        if (HasControl(allowNewlines ? text.Replace("\n", string.Empty, StringComparison.Ordinal) : text))
        {
            return $"{label} contains control characters.";
        }

        if (HasInvisible(text))
        {
            return $"{label} contains invisible formatting characters (for example bidirectional overrides).";
        }

        if (trimmed && text != text.Trim())
        {
            return $"{label} has spaces at the start or end.";
        }

        return null;
    }

    private static string? HttpsUrlProblem(JsonElement? value, string label)
    {
        if (value is not { ValueKind: JsonValueKind.String } element)
        {
            return $"{label} must be a string.";
        }

        var text = element.GetString()!;
        if (text.Length > 2048)
        {
            return $"{label} is longer than 2048 characters.";
        }

        if (HasJsWhitespace(text) || HasControl(text))
        {
            return $"{label} contains spaces or control characters.";
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri))
        {
            return $"{label} is not a valid URL.";
        }

        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            return $"{label} must start with https://.";
        }

        if (uri.UserInfo.Length > 0)
        {
            return $"{label} must not contain a user name or password.";
        }

        if (uri.Fragment.Length > 1)
        {
            return $"{label} must not contain a #fragment.";
        }

        // The ASCII (punycode) host, as JavaScript's URL parser gives it.
        var host = uri.IdnHost.ToLowerInvariant();

        // "localhost." and "intranet." are the same hosts as "localhost" and "intranet".
        if (host.EndsWith('.'))
        {
            return $"{label} has a host name that ends with a dot ({host}).";
        }

        if (host == "localhost" || host.EndsWith(".localhost", StringComparison.Ordinal) ||
            uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6)
        {
            return $"{label} must use a public host name, not {host}.";
        }

        if (!host.Contains('.'))
        {
            return $"{label} must use a fully qualified host name.";
        }

        // Every top-level domain starts with a letter; a numeric last part is an IP address in some URL parsers.
        var last = host[(host.LastIndexOf('.') + 1)..];
        if (last.Length == 0 || last[0] is < 'a' or > 'z')
        {
            return $"{label} must use a host name whose last part starts with a letter, not {host}.";
        }

        return null;
    }

    private static string? RelativeFileProblem(JsonElement? value, string label, string[] extensions)
    {
        if (value is not { ValueKind: JsonValueKind.String } element)
        {
            return $"{label} must be a string.";
        }

        var text = element.GetString()!;
        var check = RantePackagePaths.Check(text);
        if (!check.IsValid)
        {
            return $"{label}: {check.Message}";
        }

        if (check.IsDirectory)
        {
            return $"{label} must name a file, not a folder.";
        }

        if (!extensions.Contains(RanteFileTypes.ExtensionOf(text), StringComparer.Ordinal))
        {
            return $"{label} must be a {string.Join(", ", extensions.Select(e => "." + e))} file.";
        }

        return null;
    }
}
