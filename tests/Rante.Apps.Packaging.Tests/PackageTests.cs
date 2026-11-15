using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Rante.Apps.Packaging.Tests;

/// <summary>Package checks: a port of rante-apps-sdk's packages/cli/test/package.test.js, plus the reader.</summary>
public sealed class PackageTests
{
    private const int UnixMadeBy = (3 << 8) | 20;

    private static string[] Codes(RantePackageValidation result) => result.Errors.Select(e => e.Code).ToArray();

    private static uint UnixMode(string octal) => Convert.ToUInt32(octal, 8) << 16;

    private static string Sha256(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    [Fact]
    public void AValidPackagePassesAndListsItsFilesWithHashesAndContentTypes()
    {
        var zip = Samples.ZipOf(new TestEntry("assets/app.js", "console.log(1)"));
        var result = RantePackage.Validate(zip);
        Assert.Empty(result.Errors);
        Assert.True(result.IsValid);
        Assert.Equal("Hello Rante", result.Manifest!.Value.GetProperty("name").GetString());
        Assert.Equal(new[] { "assets/app.js", "icon.svg", "index.html", "manifest.json" }, result.Files.Select(f => f.Path));
        var js = result.Files[0];
        Assert.Equal("text/javascript; charset=utf-8", js.ContentType);
        Assert.Equal(Sha256(Encoding.UTF8.GetBytes("console.log(1)")), js.Sha256);
        Assert.Equal(Sha256(zip), result.PackageSha256);
        Assert.Equal(zip.LongLength, result.PackageBytes);
        Assert.Equal(result.Files.Sum(f => f.Size), result.TotalBytes);
    }

    [Fact]
    public void Step1RefusesFilesWithoutTheZipSignatureAndOversizedPackages()
    {
        Assert.Equal(new[] { "not_a_zip" }, Codes(RantePackage.Validate(Encoding.ASCII.GetBytes("MZ not a zip at all"))));
        Assert.Equal(new[] { "not_a_zip" }, Codes(RantePackage.Validate(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00 })));
        var zip = Samples.ZipOf();
        var limits = RantePackageLimits.Default with { MaxPackageBytes = zip.Length - 1 };
        Assert.Equal(new[] { "package_too_large" }, Codes(RantePackage.Validate(zip, limits)));
        Assert.Equal(50L * 1024 * 1024, RantePackageLimits.Default.MaxPackageBytes);
    }

    [Fact]
    public void Step2NeedsAValidManifestAtTheRoot()
    {
        var noManifest = TestZip.Write(new TestEntry("index.html", Samples.Index));
        Assert.Equal(new[] { "manifest_missing" }, Codes(RantePackage.Validate(noManifest)));

        var nested = TestZip.Write(new TestEntry("dist/manifest.json", "{}"), new TestEntry("dist/index.html", Samples.Index));
        var result = RantePackage.Validate(nested);
        Assert.Equal(new[] { "manifest_missing" }, Codes(result));
        Assert.Contains("found \"dist/manifest.json\"", result.Errors[0].Message);

        var badJson = TestZip.Write(new TestEntry("manifest.json", "{\"id\": "), new TestEntry("index.html", Samples.Index));
        Assert.Equal(new[] { "manifest_invalid_json" }, Codes(RantePackage.Validate(badJson)));

        var repeated = TestZip.Write(new TestEntry("manifest.json", "{\"name\":\"a\",\"name\":\"b\"}"));
        Assert.Equal(new[] { "manifest_invalid_json" }, Codes(RantePackage.Validate(repeated)));

        var badVersion = Samples.ZipWith(Samples.Bundle(m => m["version"] = "one"));
        Assert.Contains("manifest_invalid", Codes(RantePackage.Validate(badVersion)));

        var limits = RantePackageLimits.Default with { MaxManifestBytes = 10 };
        Assert.Equal(new[] { "manifest_too_large" }, Codes(RantePackage.Validate(Samples.ZipOf(), limits)));
    }

    [Fact]
    public void Step2TheEntryPointAndIconMustBeInThePackageAndExternalAppsAreNotPackages()
    {
        var noEntry = TestZip.Write(new TestEntry("manifest.json", Samples.Json(Samples.Bundle(m => m.Remove("icon")))));
        Assert.Equal(new[] { "entry_point_missing" }, Codes(RantePackage.Validate(noEntry)));
        var noIcon = TestZip.Write(new TestEntry("manifest.json", Samples.Json(Samples.Bundle())), new TestEntry("index.html", Samples.Index));
        Assert.Equal(new[] { "icon_missing" }, Codes(RantePackage.Validate(noIcon)));
        var external = TestZip.Write(new TestEntry("manifest.json", Samples.Json(Samples.External())));
        Assert.Equal(new[] { "manifest_invalid" }, Codes(RantePackage.Validate(external)));
    }

    [Theory]
    [InlineData("tools/setup.exe", "x", "file_type_forbidden")]
    [InlineData("api/index.php", "<?php", "file_type_forbidden")]
    [InlineData("deploy.sh", "rm -rf /", "file_type_forbidden")]
    [InlineData("web.config", "<configuration/>", "file_type_forbidden")]
    [InlineData("LICENSE", "MIT", "file_type_unknown")]
    [InlineData("data.sqlite", "x", "file_type_unknown")]
    [InlineData("run.js", "#!/bin/sh\necho hi", "executable_content")]
    public void Step2RefusesForbiddenAndUnknownFileTypesAndScripts(string name, string content, string code)
    {
        Assert.Equal(new[] { code }, Codes(RantePackage.Validate(Samples.ZipOf(new TestEntry(name, content)))));
    }

    [Theory]
    [InlineData("bundle.js", new byte[] { 0x4d, 0x5a, 0x90, 0x00, 0x20, 0x64, 0x69, 0x73 })]
    [InlineData("image.png", new byte[] { 0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0 })]
    [InlineData("image.png", new byte[] { 0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1 })]
    [InlineData("data.json", new byte[] { 0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2 })]
    public void Step2RefusesExecutableContentWhateverTheFileType(string name, byte[] content)
    {
        Assert.Equal(new[] { "executable_content" }, Codes(RantePackage.Validate(Samples.ZipOf(new TestEntry(name, content)))));
    }

    [Theory]
    [InlineData("../evil.js", "path_traversal")]
    [InlineData("assets/../../evil.js", "path_traversal")]
    [InlineData("/etc/cron.d/evil.js", "path_traversal")]
    [InlineData("C:/Windows/evil.js", "path_traversal")]
    [InlineData("..\\..\\evil.js", "path_invalid")]
    [InlineData("a//b.js", "path_invalid")]
    [InlineData(".env", "hidden_file")]
    [InlineData("__MACOSX/._index.html", "hidden_file")]
    public void Step3RefusesZipSlipPathsBeforeAnythingIsRead(string name, string code)
    {
        Assert.Equal(new[] { code }, Codes(RantePackage.Validate(Samples.ZipOf(new TestEntry(name, "x")))));
    }

    [Fact]
    public void Step3RefusesDuplicatesCaseOnlyDuplicatesAndSymbolicLinks()
    {
        Assert.Equal(new[] { "path_duplicate" }, Codes(RantePackage.Validate(Samples.ZipOf(new TestEntry("index.html", Samples.Index)))));
        Assert.Equal(new[] { "path_case_duplicate" }, Codes(RantePackage.Validate(Samples.ZipOf(new TestEntry("Index.html", Samples.Index)))));
        var link = new TestEntry("link.js", "/etc/passwd") { VersionMadeBy = UnixMadeBy, ExternalAttributes = UnixMode("120777") };
        Assert.Equal(new[] { "symlink" }, Codes(RantePackage.Validate(Samples.ZipOf(link))));
        var unixFile = new TestEntry("app.js", "1") { VersionMadeBy = UnixMadeBy, ExternalAttributes = UnixMode("100644") };
        Assert.Empty(Codes(RantePackage.Validate(Samples.ZipOf(unixFile))));
    }

    [Fact]
    public void Step3RefusesEntriesThatAreNotRegularFilesOrFolders()
    {
        var fifo = new TestEntry("pipe.js", "1") { VersionMadeBy = UnixMadeBy, ExternalAttributes = UnixMode("010644") };
        Assert.Equal(new[] { "zip_invalid" }, Codes(RantePackage.Validate(Samples.ZipOf(fifo))));
        var folderType = new TestEntry("app.js", "1") { VersionMadeBy = UnixMadeBy, ExternalAttributes = UnixMode("040755") };
        Assert.Equal(new[] { "zip_invalid" }, Codes(RantePackage.Validate(Samples.ZipOf(folderType))));
        var fileTypeFolder = new TestEntry("assets/", Array.Empty<byte>()) { VersionMadeBy = UnixMadeBy, ExternalAttributes = UnixMode("100644") };
        Assert.Equal(new[] { "zip_invalid" }, Codes(RantePackage.Validate(Samples.ZipOf(fileTypeFolder))));
        var folderWithData = new TestEntry("assets/", "x");
        Assert.Equal(new[] { "zip_invalid" }, Codes(RantePackage.Validate(Samples.ZipOf(folderWithData))));
        var unixFolder = new TestEntry("assets/", Array.Empty<byte>()) { VersionMadeBy = UnixMadeBy, ExternalAttributes = UnixMode("040755") };
        Assert.Empty(Codes(RantePackage.Validate(Samples.ZipOf(unixFolder))));
    }

    [Fact]
    public void Step3RefusesZipBombsByRatioAndBySize()
    {
        var zeros = new byte[2 * 1024 * 1024];
        Assert.Equal(new[] { "compression_ratio" }, Codes(RantePackage.Validate(Samples.ZipOf(new TestEntry("bomb.txt", zeros)))));
        var letters = new byte[5000];
        Array.Fill(letters, (byte)0x61);
        var small = Samples.ZipOf(new TestEntry("big.txt", letters));
        Assert.Equal(new[] { "file_too_large" }, Codes(RantePackage.Validate(small, RantePackageLimits.Default with { MaxFileBytes = 4000 })));
        Assert.Equal(new[] { "total_too_large" }, Codes(RantePackage.Validate(small, RantePackageLimits.Default with { MaxTotalBytes = 4000 })));
    }

    [Fact]
    public void FolderEntriesAreAllowedAndIgnored()
    {
        var result = RantePackage.Validate(Samples.ZipOf(new TestEntry("assets/", Array.Empty<byte>()), new TestEntry("assets/a.css", "a{}")));
        Assert.True(result.IsValid);
        Assert.DoesNotContain(result.Files, f => f.Path is "assets" or "assets/");
        Assert.Contains(result.Files, f => f.Path == "assets/a.css");
    }

    [Fact]
    public void ListsFilesInTheByteOrderOfTheirPaths()
    {
        var result = RantePackage.Validate(Samples.ZipOf(
            new TestEntry("~x.js", "1"), new TestEntry("a.js", "1"), new TestEntry("Z.js", "1"), new TestEntry("(x).js", "1")));
        Assert.Equal(new[] { "(x).js", "Z.js", "a.js", "icon.svg", "index.html", "manifest.json", "~x.js" }, result.Files.Select(f => f.Path));
    }

    [Fact]
    public void AnInvalidPackageListsNoFiles()
    {
        var result = RantePackage.Validate(Samples.ZipOf(new TestEntry("tools/setup.exe", "x")));
        Assert.False(result.IsValid);
        Assert.Empty(result.Files);
        Assert.Equal(0, result.TotalBytes);
        Assert.True(result.Manifest.HasValue);
    }

    [Fact]
    public void ChecksAStreamTheSameWayAndReadsAtMostOneByteOverTheLimit()
    {
        var zip = Samples.SampleApp();
        var fromBytes = RantePackage.Validate(zip);
        var fromStream = RantePackage.Validate(new MemoryStream(zip));
        Assert.True(fromStream.IsValid);
        Assert.Equal(fromBytes.PackageSha256, fromStream.PackageSha256);
        Assert.Equal(fromBytes.Files, fromStream.Files);

        var big = new MemoryStream(new byte[1_000_000]);
        var limits = RantePackageLimits.Default with { MaxPackageBytes = 100_000 };
        var refused = RantePackage.Validate(big, limits);
        Assert.Equal(new[] { "package_too_large" }, Codes(refused));
        Assert.Equal(100_001L, big.Position);
        Assert.Equal(100_001L, refused.PackageBytes);
    }

    [Fact]
    public void RefusesLimitsOutOfRange()
    {
        var zip = Samples.ZipOf();
        Assert.Throws<ArgumentOutOfRangeException>(() => RantePackage.Validate(zip, RantePackageLimits.Default with { MaxFileBytes = long.MaxValue }));
        Assert.Throws<ArgumentOutOfRangeException>(() => RantePackage.Validate(zip, RantePackageLimits.Default with { MaxPackageBytes = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => RantePackage.Validate(zip, RantePackageLimits.Default with { MaxCompressionRatio = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            RantePackage.Validate(new MemoryStream(zip), RantePackageLimits.Default with { MaxPackageBytes = long.MaxValue }));
    }

    [Fact]
    public void ReaderReadsTheFilesOfAValidPackage()
    {
        var reader = RantePackageReader.Open(Samples.SampleApp());
        Assert.True(reader.Validation.IsValid);
        Assert.Equal(6, reader.Validation.Files.Count);
        Assert.Equal(string.Concat(Enumerable.Repeat(Samples.AppJsLine, 20)), Encoding.UTF8.GetString(reader.ReadFile("app.js")));
        Assert.Equal(Samples.DataJson, Encoding.UTF8.GetString(reader.ReadFile("assets/data.json")));
        Assert.Throws<InvalidOperationException>(() => reader.ReadFile("missing.js"));
        Assert.Throws<InvalidOperationException>(() => reader.ReadFile("assets"));
    }

    [Fact]
    public void ReaderRefusesToReadAnInvalidPackage()
    {
        var reader = RantePackageReader.Open(Samples.ZipOf(new TestEntry("../escaped.js", "x")));
        Assert.Equal(new[] { "path_traversal" }, Codes(reader.Validation));
        Assert.Empty(reader.Validation.Files);
        Assert.Throws<InvalidOperationException>(() => reader.ReadFile("index.html"));
    }

    [Fact]
    public void ReaderNoticesWhenThePackageChangesAfterTheCheck()
    {
        var zip = Samples.ZipOf(new TestEntry("data.txt", "abcdef") { Compress = false });
        var reader = RantePackageReader.Open(zip);
        Assert.True(reader.Validation.IsValid);
        Assert.Equal("abcdef", Encoding.UTF8.GetString(reader.ReadFile("data.txt")));
        var at = zip.AsSpan().IndexOf("abcdef"u8);
        zip[at] ^= 0xff;
        Assert.Throws<InvalidDataException>(() => reader.ReadFile("data.txt"));
    }

    [Fact]
    public void ExtractWritesEveryFileOfAValidPackageAndNothingOfAnInvalidOne()
    {
        using var temp = new TempFolder();
        var output = Path.Combine(temp.Root, "out");
        var reader = RantePackageReader.Open(Samples.SampleApp());
        var written = reader.ExtractToDirectory(output);
        Assert.Equal(6, written.Count);
        Assert.Equal(Samples.DataJson, File.ReadAllText(Path.Combine(output, "assets", "data.json")));
        Assert.Equal(string.Concat(Enumerable.Repeat(Samples.AppJsLine, 20)), File.ReadAllText(Path.Combine(output, "app.js")));
        Assert.Throws<InvalidOperationException>(() => reader.ExtractToDirectory(output));

        var evil = RantePackageReader.Open(Samples.ZipOf(new TestEntry("../escaped.js", "x")));
        var target = Path.Combine(temp.Root, "evil-out");
        Assert.Throws<InvalidOperationException>(() => evil.ExtractToDirectory(target));
        Assert.False(Directory.Exists(target));
        Assert.False(File.Exists(Path.Combine(temp.Root, "escaped.js")));
    }

    [Fact]
    public void ExtractNeedsANewOrEmptyFolder()
    {
        using var temp = new TempFolder();
        var reader = RantePackageReader.Open(Samples.SampleApp());
        var empty = Directory.CreateDirectory(Path.Combine(temp.Root, "empty")).FullName;
        Assert.Equal(6, reader.ExtractToDirectory(empty).Count);
        var file = Path.Combine(temp.Root, "a-file");
        File.WriteAllText(file, "x");
        Assert.Throws<InvalidOperationException>(() => reader.ExtractToDirectory(file));
        Assert.Throws<ArgumentException>(() => reader.ExtractToDirectory(string.Empty));
    }
}
