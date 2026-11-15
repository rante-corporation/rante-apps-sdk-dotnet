using System.Collections.Frozen;
using System.Text;
using System.Text.RegularExpressions;

namespace Rante.Apps.Packaging;

/// <summary>The result of checking one path inside a package.</summary>
/// <param name="IsValid">Whether the path is acceptable.</param>
/// <param name="Path">The path without a trailing "/" (when valid).</param>
/// <param name="IsDirectory">Whether the entry is a folder entry (a name ending in "/").</param>
/// <param name="Code">path_invalid, path_traversal or hidden_file (when not valid).</param>
/// <param name="Message">Why the path is refused (when not valid).</param>
public sealed record RantePathCheck(bool IsValid, string? Path, bool IsDirectory, string? Code, string? Message);

/// <summary>
/// Path rules for files inside a .rante package (docs/package-format.md): relative, "/" separated, inside the package
/// (no zip slip), a conservative character set, no hidden files. The C# twin of packages/cli/lib/paths.js.
/// </summary>
public static partial class RantePackagePaths
{
    /// <summary>The characters a file or folder name may use.</summary>
    public const string AllowedCharacters = "A-Z a-z 0-9 . _ ~ @ + = , ( ) ! -";

    private const int MaxPathBytes = 512;
    private const int MaxSegmentBytes = 255;
    private const int MaxDepth = 32;

    // Patterns end with \z, not $: in .NET, $ also matches before a final "\n", so "a.js\n" would pass.
    [GeneratedRegex(@"^[A-Za-z0-9._~@+=,()!-]+\z", RegexOptions.CultureInvariant)]
    private static partial Regex SafeSegment();

    [GeneratedRegex(@"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|\z)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ReservedDevice();

    [GeneratedRegex(@"^[A-Za-z]:", RegexOptions.CultureInvariant)]
    private static partial Regex DriveLetter();

    private static RantePathCheck Problem(string code, string message) => new(false, null, false, code, message);

    /// <summary>Checks one archive entry name.</summary>
    public static RantePathCheck Check(string? name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return Problem("path_invalid", "An entry has an empty name.");
        }

        if (name.Contains('\\'))
        {
            return Problem("path_invalid", $"\"{name}\" contains a backslash. Paths inside a package use forward slashes.");
        }

        if (name[0] == '/')
        {
            return Problem("path_traversal", $"\"{name}\" is an absolute path. Paths must be relative.");
        }

        if (DriveLetter().IsMatch(name))
        {
            return Problem("path_traversal", $"\"{name}\" starts with a drive letter. Paths must be relative.");
        }

        var path = name;
        var isDirectory = path.EndsWith('/');
        if (isDirectory)
        {
            path = path[..^1];
        }

        if (path.Length == 0)
        {
            return Problem("path_invalid", "An entry is named \"/\".");
        }

        if (Encoding.UTF8.GetByteCount(path) > MaxPathBytes)
        {
            return Problem("path_invalid", $"\"{path[..Math.Min(60, path.Length)]}...\" is longer than {MaxPathBytes} bytes.");
        }

        var segments = path.Split('/');
        if (segments.Length > MaxDepth)
        {
            return Problem("path_invalid", $"\"{path}\" is more than {MaxDepth} folders deep.");
        }

        for (var i = 0; i < segments.Length; i++)
        {
            var segment = segments[i];
            if (segment.Length == 0)
            {
                return Problem("path_invalid", $"\"{path}\" has an empty folder name (\"//\").");
            }

            if (segment is "." or "..")
            {
                return Problem("path_traversal", $"\"{path}\" contains \"{segment}\". Paths must stay inside the package.");
            }

            if (segment == "__MACOSX")
            {
                return Problem("hidden_file", $"\"{path}\" is macOS archive metadata. Remove the __MACOSX folder.");
            }

            if (segment[0] == '.' && !(i == 0 && segment == ".well-known"))
            {
                return Problem("hidden_file", $"\"{path}\" is a hidden file or folder (its name starts with \".\"). Hidden files are not allowed.");
            }

            if (Encoding.UTF8.GetByteCount(segment) > MaxSegmentBytes)
            {
                return Problem("path_invalid", $"A name in \"{path}\" is longer than {MaxSegmentBytes} bytes.");
            }

            if (!SafeSegment().IsMatch(segment))
            {
                return Problem("path_invalid", $"\"{path}\" uses characters outside {AllowedCharacters}.");
            }

            if (segment.EndsWith('.'))
            {
                return Problem("path_invalid", $"\"{path}\" has a name that ends with a dot.");
            }

            if (ReservedDevice().IsMatch(segment))
            {
                return Problem("path_invalid", $"\"{path}\" uses a reserved device name ({segment}).");
            }
        }

        return new RantePathCheck(true, path, isDirectory, null, null);
    }
}

/// <summary>The result of checking a file's type.</summary>
/// <param name="IsAllowed">Whether packages may contain the file.</param>
/// <param name="Extension">The lower-case extension.</param>
/// <param name="ContentType">The Content-Type Rante serves the file with (when allowed).</param>
/// <param name="Code">file_type_forbidden or file_type_unknown (when not allowed).</param>
/// <param name="Message">Why the file is refused (when not allowed).</param>
public sealed record RanteFileTypeCheck(bool IsAllowed, string Extension, string? ContentType, string? Code, string? Message);

/// <summary>
/// The file types a .rante package may contain and their Content-Types (served with nosniff); everything else is
/// refused. The C# twin of packages/cli/lib/mime.js.
/// </summary>
public static class RanteFileTypes
{
    /// <summary>Allowed extensions and their Content-Types.</summary>
    public static readonly IReadOnlyDictionary<string, string> ContentTypes = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["html"] = "text/html; charset=utf-8",
        ["htm"] = "text/html; charset=utf-8",
        ["css"] = "text/css; charset=utf-8",
        ["js"] = "text/javascript; charset=utf-8",
        ["mjs"] = "text/javascript; charset=utf-8",
        ["json"] = "application/json; charset=utf-8",
        ["map"] = "application/json; charset=utf-8",
        ["webmanifest"] = "application/manifest+json; charset=utf-8",
        ["txt"] = "text/plain; charset=utf-8",
        ["md"] = "text/markdown; charset=utf-8",
        ["csv"] = "text/csv; charset=utf-8",
        ["xml"] = "application/xml; charset=utf-8",
        ["wasm"] = "application/wasm",
        ["pdf"] = "application/pdf",
        ["png"] = "image/png",
        ["jpg"] = "image/jpeg",
        ["jpeg"] = "image/jpeg",
        ["gif"] = "image/gif",
        ["webp"] = "image/webp",
        ["avif"] = "image/avif",
        ["svg"] = "image/svg+xml",
        ["ico"] = "image/x-icon",
        ["bmp"] = "image/bmp",
        ["woff"] = "font/woff",
        ["woff2"] = "font/woff2",
        ["ttf"] = "font/ttf",
        ["otf"] = "font/otf",
        ["mp3"] = "audio/mpeg",
        ["m4a"] = "audio/mp4",
        ["aac"] = "audio/aac",
        ["wav"] = "audio/wav",
        ["ogg"] = "audio/ogg",
        ["oga"] = "audio/ogg",
        ["flac"] = "audio/flac",
        ["mp4"] = "video/mp4",
        ["webm"] = "video/webm",
        ["ogv"] = "video/ogg",
        ["glb"] = "model/gltf-binary",
        ["gltf"] = "model/gltf+json",
    }.ToFrozenDictionary(StringComparer.Ordinal);

    private static readonly HashSet<string> Forbidden = new(StringComparer.Ordinal)
    {
        "exe", "dll", "com", "bat", "cmd", "msi", "msp", "msix", "appx", "scr", "pif", "cpl", "sys", "drv", "ocx",
        "vbs", "vbe", "wsf", "wsh", "hta", "lnk", "reg", "ps1", "psm1", "psd1",
        "sh", "bash", "zsh", "ksh", "csh", "fish", "command", "run", "out",
        "php", "phtml", "php3", "php4", "php5", "php7", "phar",
        "asp", "aspx", "ashx", "asmx", "axd", "cshtml", "vbhtml", "jsp", "jspx", "cfm", "cgi", "fcgi",
        "pl", "pm", "py", "pyc", "pyo", "rb", "lua", "tcl",
        "jar", "war", "ear", "class", "so", "dylib", "ko", "bin", "elf", "o", "a", "lib",
        "app", "apk", "aab", "ipa", "dmg", "pkg", "deb", "rpm", "snap", "iso", "img", "vhd", "vhdx",
        "htaccess", "htpasswd", "config", "ini", "env", "conf",
        "swf", "xap", "xbap",
    };

    /// <summary>The lower-case extension of a path ("" when it has none).</summary>
    public static string ExtensionOf(string path)
    {
        var name = path[(path.LastIndexOf('/') + 1)..];
        var dot = name.LastIndexOf('.');
        return dot > 0 ? name[(dot + 1)..].ToLowerInvariant() : string.Empty;
    }

    /// <summary>Checks whether a package may contain a file with this path.</summary>
    public static RanteFileTypeCheck Check(string path)
    {
        var extension = ExtensionOf(path);
        if (extension.Length > 0 && ContentTypes.TryGetValue(extension, out var contentType))
        {
            return new RanteFileTypeCheck(true, extension, contentType, null, null);
        }

        if (Forbidden.Contains(extension))
        {
            return new RanteFileTypeCheck(false, extension, null, "file_type_forbidden",
                $"\"{path}\" is a .{extension} file. Executables, scripts for servers or shells, and server configuration are not allowed in a package.");
        }

        return new RanteFileTypeCheck(false, extension, null, "file_type_unknown", extension.Length > 0
            ? $"\"{path}\" has a file type (.{extension}) that packages may not contain. See docs/package-format.md for the list."
            : $"\"{path}\" has no file extension. Every file needs one of the allowed extensions.");
    }

    /// <summary>Executable and script signatures: a description when the content looks executable, otherwise null.</summary>
    public static string? SniffExecutable(ReadOnlySpan<byte> data)
    {
        if (data.Length >= 2 && data[0] == 0x4d && data[1] == 0x5a)
        {
            return "a Windows executable (MZ header)";
        }

        if (data.Length >= 4 && data[0] == 0x7f && data[1] == 0x45 && data[2] == 0x4c && data[3] == 0x46)
        {
            return "a Linux executable (ELF header)";
        }

        if (data.Length >= 4)
        {
            var magic = (uint)(data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]);
            if (magic is 0xfeedface or 0xfeedfacf or 0xcefaedfe or 0xcffaedfe)
            {
                return "a macOS executable (Mach-O header)";
            }

            if (magic == 0xcafebabe)
            {
                return "a Mach-O universal binary or Java class file";
            }
        }

        if (data.Length >= 2 && data[0] == 0x23 && data[1] == 0x21)
        {
            return "a script with an interpreter line (#!)";
        }

        return null;
    }
}
