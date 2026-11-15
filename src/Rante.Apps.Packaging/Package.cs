using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Rante.Apps.Packaging;

/// <summary>The limits every package must stay within. <see cref="Default"/> holds the values Rante's servers use.</summary>
public sealed record RantePackageLimits
{
    private const long MiB = 1024 * 1024;

    /// <summary>The limits Rante's servers use (docs/package-format.md).</summary>
    public static RantePackageLimits Default { get; } = new();

    /// <summary>The package's size. Default 50 MiB.</summary>
    public long MaxPackageBytes { get; init; } = 50 * MiB;

    /// <summary>Entries in the archive. Default 5000.</summary>
    public int MaxEntries { get; init; } = 5000;

    /// <summary>One file, unpacked. Default 50 MiB.</summary>
    public long MaxFileBytes { get; init; } = 50 * MiB;

    /// <summary>All files, unpacked. Default 200 MiB.</summary>
    public long MaxTotalBytes { get; init; } = 200 * MiB;

    /// <summary>manifest.json. Default 64 KiB.</summary>
    public long MaxManifestBytes { get; init; } = 64 * 1024;

    /// <summary>Files from this size on must not expand more than <see cref="MaxCompressionRatio"/> times. Default 1 MiB.</summary>
    public long RatioCheckBytes { get; init; } = 1 * MiB;

    /// <summary>The largest compression ratio allowed for large files. Default 200.</summary>
    public long MaxCompressionRatio { get; init; } = 200;
}

/// <summary>One file of a valid package.</summary>
/// <param name="Path">Its path inside the package, with "/" separators.</param>
/// <param name="Size">Its size, unpacked.</param>
/// <param name="CompressedSize">Its size inside the archive.</param>
/// <param name="Method">deflate or stored.</param>
/// <param name="ContentType">The Content-Type Rante serves it with.</param>
/// <param name="Sha256">The SHA-256 of its content, lower-case hex.</param>
public sealed record RantePackageFile(string Path, long Size, long CompressedSize, string Method, string ContentType, string Sha256);

/// <summary>The outcome of checking a package.</summary>
public sealed class RantePackageValidation
{
    internal RantePackageValidation(
        IReadOnlyList<RantePackageIssue> errors,
        IReadOnlyList<RantePackageIssue> warnings,
        JsonElement? manifest,
        IReadOnlyList<RantePackageFile> files,
        string packageSha256,
        long packageBytes,
        long totalBytes)
    {
        Errors = errors;
        Warnings = warnings;
        Manifest = manifest;
        Files = files;
        PackageSha256 = packageSha256;
        PackageBytes = packageBytes;
        TotalBytes = totalBytes;
    }

    /// <summary>Whether the package passed every check.</summary>
    public bool IsValid => Errors.Count == 0;

    /// <summary>Problems; empty when the package is valid.</summary>
    public IReadOnlyList<RantePackageIssue> Errors { get; }

    /// <summary>Things that do not make the package invalid.</summary>
    public IReadOnlyList<RantePackageIssue> Warnings { get; }

    /// <summary>manifest.json, when it could be read (also when it breaks manifest rules).</summary>
    public JsonElement? Manifest { get; }

    /// <summary>The files, sorted by the bytes of their paths; empty unless the package is valid.</summary>
    public IReadOnlyList<RantePackageFile> Files { get; }

    /// <summary>The SHA-256 of the whole package, lower-case hex.</summary>
    public string PackageSha256 { get; }

    /// <summary>The package's size.</summary>
    public long PackageBytes { get; }

    /// <summary>The files' total size, unpacked.</summary>
    public long TotalBytes { get; }
}

/// <summary>
/// Checks .rante packages the way Rante's servers check uploads (docs/package-format.md), in the same order as
/// rante-apps-sdk's <c>rante validate</c>: (1) the ZIP signature and the size limit; (2) manifest.json in memory, the
/// entry point and icon present, allowed file types only; (3) every path relative and inside the package, no
/// duplicates, links or zip bombs. Nothing is inflated unless the archive's structure and paths pass.
/// </summary>
public static class RantePackage
{
    private const string ManifestName = "manifest.json";
    private const int UnixHost = 3;
    private const uint SIfMt = 0xF000;
    private const uint SIfReg = 0x8000;
    private const uint SIfDir = 0x4000;
    private const uint SIfLnk = 0xA000;
    private static readonly byte[] ZipSignature = [0x50, 0x4b, 0x03, 0x04];

    /// <summary>Checks a package held in memory.</summary>
    /// <exception cref="ArgumentOutOfRangeException">A limit is out of its range (sizes must fit in a byte array).</exception>
    public static RantePackageValidation Validate(byte[] package, RantePackageLimits? limits = null) => Inspect(package, limits).Validation;

    /// <summary>
    /// Checks a package read from a stream. At most <see cref="RantePackageLimits.MaxPackageBytes"/> + 1 bytes are read;
    /// a longer stream is refused with package_too_large and <see cref="RantePackageValidation.PackageBytes"/> is the
    /// number of bytes read.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">A limit is out of its range (sizes must fit in a byte array).</exception>
    public static RantePackageValidation Validate(Stream stream, RantePackageLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var max = Checked(limits).MaxPackageBytes;
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = stream.Read(chunk, 0, (int)Math.Min(chunk.Length, max + 1 - buffer.Length))) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > max)
            {
                return new RantePackageValidation(
                    [new RantePackageIssue("package_too_large", $"The package is larger than {max} bytes, the limit.")],
                    [], null, [], string.Empty, buffer.Length, 0);
            }
        }

        return Validate(buffer.ToArray(), limits);
    }

    /// <summary>The limits to use, after checking that every value is in range.</summary>
    private static RantePackageLimits Checked(RantePackageLimits? limits)
    {
        limits ??= RantePackageLimits.Default;
        static void Require(long value, long min, long max, string name)
        {
            if (value < min || value > max)
            {
                throw new ArgumentOutOfRangeException("limits", value, $"{name} must be between {min} and {max}.");
            }
        }

        // The package, one file and manifest.json are each held in a byte array.
        Require(limits.MaxPackageBytes, 1, Array.MaxLength, nameof(RantePackageLimits.MaxPackageBytes));
        Require(limits.MaxEntries, 1, int.MaxValue, nameof(RantePackageLimits.MaxEntries));
        Require(limits.MaxFileBytes, 0, Array.MaxLength, nameof(RantePackageLimits.MaxFileBytes));
        Require(limits.MaxTotalBytes, 0, long.MaxValue, nameof(RantePackageLimits.MaxTotalBytes));
        Require(limits.MaxManifestBytes, 0, Array.MaxLength, nameof(RantePackageLimits.MaxManifestBytes));
        Require(limits.RatioCheckBytes, 0, long.MaxValue, nameof(RantePackageLimits.RatioCheckBytes));
        Require(limits.MaxCompressionRatio, 1, int.MaxValue, nameof(RantePackageLimits.MaxCompressionRatio));
        return limits;
    }

    internal static string Sha256Hex(ReadOnlySpan<byte> data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    internal sealed record Inspection(RantePackageValidation Validation, Dictionary<string, ZipEntry> Entries);

    private static bool IsSymlink(ZipEntry e) => (e.VersionMadeBy >> 8) == UnixHost && ((e.ExternalAttributes >> 16) & SIfMt) == SIfLnk;

    private static uint UnixType(ZipEntry e) => (e.VersionMadeBy >> 8) == UnixHost ? (e.ExternalAttributes >> 16) & SIfMt : 0;

    internal static Inspection Inspect(byte[] buffer, RantePackageLimits? limits)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        limits = Checked(limits);
        var errors = new List<RantePackageIssue>();
        var warnings = new List<RantePackageIssue>();
        var packageSha256 = Sha256Hex(buffer);
        var entriesByPath = new Dictionary<string, ZipEntry>(StringComparer.Ordinal);

        Inspection Done(JsonElement? manifest, List<RantePackageFile> files, long total)
        {
            if (errors.Count > 0)
            {
                files.Clear();
                total = 0;
            }

            files.Sort((a, b) => CompareUtf8(a.Path, b.Path));
            return new Inspection(new RantePackageValidation(errors, warnings, manifest, files, packageSha256, buffer.LongLength, total), entriesByPath);
        }

        // Step 1: size and signature.
        if (buffer.LongLength > limits.MaxPackageBytes)
        {
            errors.Add(new RantePackageIssue("package_too_large",
                $"The package is {buffer.LongLength} bytes; the limit is {limits.MaxPackageBytes}."));
            return Done(null, [], 0);
        }

        if (buffer.Length < 4 || !buffer.AsSpan(0, 4).SequenceEqual(ZipSignature))
        {
            errors.Add(new RantePackageIssue("not_a_zip",
                "The file does not start with the ZIP signature 50 4B 03 04, so it is not a .rante package."));
            return Done(null, [], 0);
        }

        List<ZipEntry> entries;
        try
        {
            entries = StrictZip.Read(buffer, limits.MaxEntries);
        }
        catch (ZipFormatException e)
        {
            errors.Add(new RantePackageIssue(e.Code, e.Message, e.Path));
            return Done(null, [], 0);
        }

        // Step 3 (paths) from the central directory alone.
        var files = new List<(ZipEntry Entry, string Path, string ContentType)>();
        var exact = new HashSet<string>(StringComparer.Ordinal);
        var folded = new Dictionary<string, string>(StringComparer.Ordinal);
        long declaredTotal = 0;
        var totalReported = false;
        foreach (var entry in entries)
        {
            var check = RantePackagePaths.Check(entry.Name);
            if (!check.IsValid)
            {
                errors.Add(new RantePackageIssue(check.Code!, check.Message!, entry.Name));
                continue;
            }

            var path = check.Path!;
            if (IsSymlink(entry))
            {
                errors.Add(new RantePackageIssue("symlink", $"\"{path}\" is a symbolic link. Links are not allowed in a package.", path));
                continue;
            }

            var type = UnixType(entry);
            if (check.IsDirectory)
            {
                if (entry.UncompressedSize != 0)
                {
                    errors.Add(new RantePackageIssue("zip_invalid", $"The folder entry \"{entry.Name}\" has data.", path));
                }

                if (type != 0 && type != SIfDir)
                {
                    errors.Add(new RantePackageIssue("zip_invalid", $"\"{entry.Name}\" is not a regular folder.", path));
                }

                continue;
            }

            if (type != 0 && type != SIfReg)
            {
                errors.Add(new RantePackageIssue("zip_invalid", $"\"{path}\" is not a regular file.", path));
                continue;
            }

            if (!exact.Add(path))
            {
                errors.Add(new RantePackageIssue("path_duplicate", $"\"{path}\" appears twice in the archive.", path));
                continue;
            }

            var lower = path.ToLowerInvariant();
            if (folded.TryGetValue(lower, out var other))
            {
                errors.Add(new RantePackageIssue("path_case_duplicate", $"\"{path}\" and \"{other}\" differ only in upper and lower case.", path));
                continue;
            }

            folded[lower] = path;
            var fileType = RanteFileTypes.Check(path);
            if (!fileType.IsAllowed)
            {
                errors.Add(new RantePackageIssue(fileType.Code!, fileType.Message!, path));
                continue;
            }

            if (entry.UncompressedSize > limits.MaxFileBytes)
            {
                errors.Add(new RantePackageIssue("file_too_large",
                    $"\"{path}\" is {entry.UncompressedSize} bytes; the limit per file is {limits.MaxFileBytes}.", path));
                continue;
            }

            if (entry.UncompressedSize >= limits.RatioCheckBytes && entry.UncompressedSize > entry.CompressedSize * limits.MaxCompressionRatio)
            {
                errors.Add(new RantePackageIssue("compression_ratio",
                    $"\"{path}\" expands more than {limits.MaxCompressionRatio} times ({entry.CompressedSize} to {entry.UncompressedSize} bytes).", path));
                continue;
            }

            declaredTotal += entry.UncompressedSize;
            if (declaredTotal > limits.MaxTotalBytes && !totalReported)
            {
                errors.Add(new RantePackageIssue("total_too_large", $"The files add up to more than {limits.MaxTotalBytes} bytes when unpacked."));
                totalReported = true;
            }

            files.Add((entry, path, fileType.ContentType!));
            entriesByPath[path] = entry;
        }

        // Step 2: manifest.json at the root.
        JsonElement? manifest = null;
        var manifestFile = files.FirstOrDefault(f => f.Path == ManifestName);
        if (manifestFile.Entry is null)
        {
            var nested = entries.Select(e => e.Name).FirstOrDefault(n => n.EndsWith("/" + ManifestName, StringComparison.Ordinal));
            errors.Add(new RantePackageIssue("manifest_missing", nested is not null
                ? $"manifest.json must be at the root of the package; found \"{nested}\". Pack the folder that contains manifest.json."
                : "The package has no manifest.json at its root."));
        }
        else if (manifestFile.Entry.UncompressedSize > limits.MaxManifestBytes)
        {
            errors.Add(new RantePackageIssue("manifest_too_large", $"manifest.json is larger than {limits.MaxManifestBytes} bytes.", ManifestName));
        }
        else
        {
            try
            {
                var parsed = RanteManifest.Parse(StrictZip.ReadData(buffer, manifestFile.Entry));
                errors.AddRange(parsed.Errors);
                warnings.AddRange(parsed.Warnings);
                manifest = parsed.Manifest;
            }
            catch (ZipFormatException e)
            {
                errors.Add(new RantePackageIssue(e.Code, e.Message, ManifestName));
            }
        }

        // Read every file only when the archive passed the checks above.
        var result = new List<RantePackageFile>();
        long total = 0;
        if (errors.Count == 0)
        {
            foreach (var f in files)
            {
                byte[] data;
                try
                {
                    data = StrictZip.ReadData(buffer, f.Entry);
                }
                catch (ZipFormatException e)
                {
                    errors.Add(new RantePackageIssue(e.Code, e.Message, f.Path));
                    continue;
                }

                if (RanteFileTypes.SniffExecutable(data) is { } executable)
                {
                    errors.Add(new RantePackageIssue("executable_content", $"\"{f.Path}\" contains {executable}.", f.Path));
                    continue;
                }

                result.Add(new RantePackageFile(f.Path, data.LongLength, f.Entry.CompressedSize,
                    f.Entry.Method == StrictZip.MethodDeflate ? "deflate" : "stored", f.ContentType, Sha256Hex(data)));
                total += data.LongLength;
            }
        }

        // The manifest must describe this package.
        if (manifest is { } m && errors.Count == 0)
        {
            var hosting = m.TryGetProperty("hosting", out var h) && h.ValueKind == JsonValueKind.String ? h.GetString() : null;
            if (hosting != "bundle")
            {
                errors.Add(new RantePackageIssue("manifest_invalid",
                    "A .rante package holds a bundle app (\"hosting\": \"bundle\"). External apps are registered with their manifest.json alone.", ManifestName));
            }
            else
            {
                var entryPoint = m.GetProperty("entryPoint").GetString()!;
                if (!exact.Contains(entryPoint))
                {
                    errors.Add(new RantePackageIssue("entry_point_missing", $"The entry point \"{entryPoint}\" is not in the package.", ManifestName));
                }

                if (m.TryGetProperty("icon", out var icon) && icon.ValueKind == JsonValueKind.String && !exact.Contains(icon.GetString()!))
                {
                    errors.Add(new RantePackageIssue("icon_missing", $"The icon \"{icon.GetString()}\" is not in the package.", ManifestName));
                }
            }
        }

        return Done(manifest, result, total);
    }

    private static int CompareUtf8(string a, string b) => Encoding.UTF8.GetBytes(a).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(b));
}

/// <summary>
/// A checked package whose files can be read (for example to store them under apps/{id}/{version}/) or extracted.
/// Every read checks the file's size, CRC-32 and SHA-256 again.
/// </summary>
public sealed class RantePackageReader
{
    private readonly byte[] _package;
    private readonly Dictionary<string, ZipEntry> _entries;
    private readonly Dictionary<string, RantePackageFile> _files;

    private RantePackageReader(byte[] package, RantePackage.Inspection inspection)
    {
        _package = package;
        _entries = inspection.Entries;
        Validation = inspection.Validation;
        _files = Validation.Files.ToDictionary(f => f.Path, StringComparer.Ordinal);
    }

    /// <summary>The outcome of the checks.</summary>
    public RantePackageValidation Validation { get; }

    /// <summary>
    /// Checks a package and returns a reader for it (also when it is invalid: see <see cref="Validation"/>). The reader
    /// keeps <paramref name="package"/> without copying it: do not change the array while you use the reader.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">A limit is out of its range (sizes must fit in a byte array).</exception>
    public static RantePackageReader Open(byte[] package, RantePackageLimits? limits = null) =>
        new(package, RantePackage.Inspect(package, limits));

    /// <summary>The content of one file of a valid package.</summary>
    /// <exception cref="InvalidOperationException">The package is not valid, or has no such file.</exception>
    /// <exception cref="InvalidDataException">The package's bytes changed after it was checked.</exception>
    public byte[] ReadFile(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (!Validation.IsValid)
        {
            throw new InvalidOperationException("The package is not valid.");
        }

        if (!_files.TryGetValue(path, out var file) || !_entries.TryGetValue(path, out var entry))
        {
            throw new InvalidOperationException($"The package has no file \"{path}\".");
        }

        byte[] data;
        try
        {
            data = StrictZip.ReadData(_package, entry);
        }
        catch (ZipFormatException e)
        {
            throw new InvalidDataException($"\"{path}\" no longer reads back ({e.Message}). Was the array changed after the package was checked?", e);
        }

        if (RantePackage.Sha256Hex(data) != file.Sha256)
        {
            throw new InvalidDataException($"The content of \"{path}\" changed since the package was checked.");
        }

        return data;
    }

    /// <summary>
    /// Writes the files of a valid package into a new or empty folder. Nothing is written unless the package is valid,
    /// and every file's final path is checked to be inside the folder.
    /// </summary>
    /// <returns>The paths written.</returns>
    /// <exception cref="InvalidOperationException">The package is not valid, or the folder is not empty.</exception>
    /// <exception cref="InvalidDataException">The package's bytes changed after it was checked.</exception>
    public IReadOnlyList<string> ExtractToDirectory(string directory)
    {
        ArgumentException.ThrowIfNullOrEmpty(directory);
        if (!Validation.IsValid)
        {
            throw new InvalidOperationException("The package is not valid.");
        }

        var root = Path.GetFullPath(directory);
        if (Directory.Exists(root))
        {
            if (Directory.EnumerateFileSystemEntries(root).Any())
            {
                throw new InvalidOperationException($"\"{directory}\" exists and is not empty.");
            }
        }
        else if (File.Exists(root))
        {
            throw new InvalidOperationException($"\"{directory}\" is a file.");
        }
        else
        {
            Directory.CreateDirectory(root);
        }

        var prefix = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        var written = new List<string>();
        foreach (var file in Validation.Files)
        {
            var target = Path.GetFullPath(Path.Combine(root, file.Path.Replace('/', Path.DirectorySeparatorChar)));
            if (!target.StartsWith(prefix, StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"Refusing to write outside the folder: {file.Path}");
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            var data = ReadFile(file.Path);
            using (var stream = new FileStream(target, FileMode.CreateNew, FileAccess.Write))
            {
                stream.Write(data);
            }

            written.Add(file.Path);
        }

        return written;
    }
}
