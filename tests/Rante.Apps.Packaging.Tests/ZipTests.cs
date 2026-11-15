using System.Globalization;
using System.Text;
using Xunit;

namespace Rante.Apps.Packaging.Tests;

/// <summary>The strict ZIP reader: a port of rante-apps-sdk's packages/cli/test/zip.test.js, plus C#-only cases.</summary>
public sealed class ZipTests
{
    private const int MaxEntries = 5000;

    private static readonly string Hello = string.Concat(Enumerable.Repeat("<p>hello</p>", 50));

    private static byte[] Sample() => TestZip.Write(
        new TestEntry("manifest.json", "{\"a\":1}"),
        new TestEntry("index.html", Hello),
        new TestEntry("empty.txt", Array.Empty<byte>()),
        new TestEntry("img/pixel.png", new byte[] { 0x89, 0x50, 0x4e, 0x47, 1, 2, 3 }, Compress: false));

    private static void ExpectZipError(Action action, string code)
    {
        var e = Assert.Throws<ZipFormatException>(action);
        Assert.Equal(code, e.Code);
    }

    private static byte[] Copy(byte[] zip) => (byte[])zip.Clone();

    [Fact]
    public void ReadsBackEntriesDeflatedOnlyWhenItHelps()
    {
        var zip = Sample();
        Assert.Equal(new byte[] { 0x50, 0x4b, 0x03, 0x04 }, zip[..4]);
        var entries = StrictZip.Read(zip, MaxEntries);
        Assert.Equal(new[] { "manifest.json", "index.html", "empty.txt", "img/pixel.png" }, entries.Select(e => e.Name));
        Assert.Equal(StrictZip.MethodDeflate, entries[1].Method);
        Assert.Equal(Hello, Encoding.UTF8.GetString(StrictZip.ReadData(zip, entries[1])));
        Assert.Equal(StrictZip.MethodStored, entries[3].Method);
        Assert.Empty(StrictZip.ReadData(zip, entries[2]));
    }

    [Fact]
    public void AcceptsAnArchiveCommentThatEndsExactlyAtTheEndOfTheFile()
    {
        byte[] withComment = [.. Sample(), .. Encoding.ASCII.GetBytes("hi")];
        TestZip.PutUInt16(withComment, withComment.Length - 2 - 2, 2);
        Assert.Equal(4, StrictZip.Read(withComment, MaxEntries).Count);
    }

    [Fact]
    public void RefusesALongArchiveComment()
    {
        var comment = new byte[1025];
        byte[] zip = [.. Sample(), .. comment];
        TestZip.PutUInt16(zip, zip.Length - comment.Length - 2, (ushort)comment.Length);
        ExpectZipError(() => StrictZip.Read(zip, MaxEntries), "zip_invalid");
    }

    [Fact]
    public void RefusesTruncatedAndDamagedArchives()
    {
        var zip = Sample();
        var truncated = zip[..^5];
        ExpectZipError(() => StrictZip.Read(truncated, MaxEntries), "zip_invalid");
        var tiny = Encoding.ASCII.GetBytes("PK");
        ExpectZipError(() => StrictZip.Read(tiny, MaxEntries), "zip_invalid");
        byte[] extra = [.. zip, .. Encoding.ASCII.GetBytes("trailing")];
        ExpectZipError(() => StrictZip.Read(extra, MaxEntries), "zip_invalid");
    }

    [Fact]
    public void RefusesZip64AndSplitArchives()
    {
        var zip = Sample();
        var eocd = zip.Length - 22;
        var z64 = Copy(zip);
        TestZip.PutUInt16(z64, eocd + 10, 0xffff);
        ExpectZipError(() => StrictZip.Read(z64, MaxEntries), "zip64_not_supported");
        var split = Copy(zip);
        TestZip.PutUInt16(split, eocd + 4, 1);
        ExpectZipError(() => StrictZip.Read(split, MaxEntries), "zip_invalid");
    }

    [Fact]
    public void RefusesAZip64LocatorAndZip64EntrySizes()
    {
        var zip = Sample();
        var locator = new byte[20];
        TestZip.PutUInt32(locator, 0, 0x07064b50);
        byte[] withLocator = [.. zip[..^22], .. locator, .. zip[^22..]];
        ExpectZipError(() => StrictZip.Read(withLocator, MaxEntries), "zip64_not_supported");
        var sizes = Copy(zip);
        TestZip.PutUInt32(sizes, TestZip.CentralOffsets(sizes)[0] + 20, 0xffffffff);
        ExpectZipError(() => StrictZip.Read(sizes, MaxEntries), "zip64_not_supported");
    }

    [Fact]
    public void RefusesEncryptedEntriesAndUnsupportedCompressionMethods()
    {
        var zip = Sample();
        var first = TestZip.CentralOffsets(zip)[0];
        var encrypted = Copy(zip);
        TestZip.PutUInt16(encrypted, first + 8, (ushort)(TestZip.GetUInt16(zip, first + 8) | 1));
        ExpectZipError(() => StrictZip.Read(encrypted, MaxEntries), "zip_encrypted");
        var bzip = Copy(zip);
        TestZip.PutUInt16(bzip, first + 10, 12);
        ExpectZipError(() => StrictZip.Read(bzip, MaxEntries), "zip_method_unsupported");
    }

    [Fact]
    public void RefusesALocalHeaderThatNamesADifferentFile()
    {
        var zip = Sample();
        zip[30] = (byte)'X'; // first byte of the first local file name
        ExpectZipError(() => StrictZip.Read(zip, MaxEntries), "zip_entry_mismatch");
    }

    [Fact]
    public void RefusesTwoCentralEntriesThatPointAtTheSameLocalHeader()
    {
        var zip = Sample();
        TestZip.PutUInt32(zip, TestZip.CentralOffsets(zip)[1] + 42, 0);
        ExpectZipError(() => StrictZip.Read(zip, MaxEntries), "zip_entry_mismatch");
    }

    [Fact]
    public void RefusesOverlappingEntries()
    {
        var zip = TestZip.Write(new TestEntry("a.txt", "aaaa") { Compress = false }, new TestEntry("b.txt", "bbbb") { Compress = false });
        // Grow the first entry so its data runs over the second entry's local header (in both headers, consistently).
        var cdA = TestZip.CentralOffsets(zip)[0];
        foreach (var offset in new[] { 18, 22, cdA + 20, cdA + 24 })
        {
            TestZip.PutUInt32(zip, offset, 10);
        }

        ExpectZipError(() => StrictZip.Read(zip, MaxEntries), "zip_entry_overlap");
    }

    [Fact]
    public void RefusesDataBeforeTheFirstEntry()
    {
        byte[] prefixed = [.. Encoding.ASCII.GetBytes("JUNK"), .. Sample()];
        // Shift every offset by 4 so the structure stays self-consistent apart from the prefix.
        var eocd = prefixed.Length - 22;
        TestZip.PutUInt32(prefixed, eocd + 16, TestZip.GetUInt32(prefixed, eocd + 16) + 4);
        foreach (var offset in TestZip.CentralOffsets(prefixed))
        {
            TestZip.PutUInt32(prefixed, offset + 42, TestZip.GetUInt32(prefixed, offset + 42) + 4);
        }

        ExpectZipError(() => StrictZip.Read(prefixed, MaxEntries), "zip_invalid");
    }

    [Fact]
    public void ChecksTheCrcWhenReadingData()
    {
        var zip = TestZip.Write(new TestEntry("a.txt", "abcdef") { Compress = false });
        zip[30 + "a.txt".Length] ^= 0xff;
        var entries = StrictZip.Read(zip, MaxEntries);
        ExpectZipError(() => StrictZip.ReadData(zip, entries[0]), "zip_crc_mismatch");
    }

    [Fact]
    public void NeverInflatesBeyondTheDeclaredSize()
    {
        var big = new byte[100000];
        Array.Fill(big, (byte)0x61);
        var zip = TestZip.Write(new TestEntry("a.txt", big));
        // Claim the entry is only 1000 bytes in both headers.
        TestZip.PutUInt32(zip, TestZip.CentralOffsets(zip)[0] + 24, 1000);
        TestZip.PutUInt32(zip, 22, 1000);
        var entries = StrictZip.Read(zip, MaxEntries);
        Assert.Equal(StrictZip.MethodDeflate, entries[0].Method);
        Assert.True(entries[0].CompressedSize < 1000);
        ExpectZipError(() => StrictZip.ReadData(zip, entries[0]), "zip_size_mismatch");
    }

    [Fact]
    public void RefusesDataShorterThanTheDeclaredSize()
    {
        var zip = TestZip.Write(new TestEntry("a.txt", Hello));
        var cd = TestZip.CentralOffsets(zip)[0];
        var declared = TestZip.GetUInt32(zip, cd + 24) + 10;
        TestZip.PutUInt32(zip, cd + 24, declared);
        TestZip.PutUInt32(zip, 22, declared);
        var entries = StrictZip.Read(zip, MaxEntries);
        ExpectZipError(() => StrictZip.ReadData(zip, entries[0]), "zip_size_mismatch");

        var stored = TestZip.Write(new TestEntry("a.txt", "abcdef") { Compress = false });
        var cdStored = TestZip.CentralOffsets(stored)[0];
        TestZip.PutUInt32(stored, cdStored + 24, 5);
        TestZip.PutUInt32(stored, 22, 5);
        var storedEntries = StrictZip.Read(stored, MaxEntries);
        ExpectZipError(() => StrictZip.ReadData(stored, storedEntries[0]), "zip_size_mismatch");
    }

    [Fact]
    public void RefusesDamagedDeflateData()
    {
        var zip = TestZip.Write(new TestEntry("a.txt", Hello));
        var entries = StrictZip.Read(zip, MaxEntries);
        Assert.Equal(StrictZip.MethodDeflate, entries[0].Method);
        zip[(int)entries[0].DataOffset] = 0xff; // a final block of the reserved type 3
        ExpectZipError(() => StrictZip.ReadData(zip, entries[0]), "zip_invalid");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ReadsEntriesWithADataDescriptor(bool signature)
    {
        var zip = TestZip.Write(
            new TestEntry("a.txt", Hello) { DataDescriptor = true, DescriptorSignature = signature },
            new TestEntry("b.txt", "bbb") { DataDescriptor = true, DescriptorSignature = signature });
        var entries = StrictZip.Read(zip, MaxEntries);
        Assert.Equal(Hello, Encoding.UTF8.GetString(StrictZip.ReadData(zip, entries[0])));
        Assert.Equal("bbb", Encoding.UTF8.GetString(StrictZip.ReadData(zip, entries[1])));
    }

    [Fact]
    public void RefusesADataDescriptorThatDisagreesOrIsMissing()
    {
        var zip = TestZip.Write(new TestEntry("a.txt", "abcdef") { Compress = false, DataDescriptor = true });
        var descriptor = 30 + "a.txt".Length + 6; // signature, CRC, compressed size, size
        var wrong = Copy(zip);
        TestZip.PutUInt32(wrong, descriptor + 8, 7);
        ExpectZipError(() => StrictZip.Read(wrong, MaxEntries), "zip_entry_mismatch");

        byte[] missing = [.. zip[..descriptor], .. zip[(descriptor + 16)..]];
        var eocd = missing.Length - 22;
        TestZip.PutUInt32(missing, eocd + 16, TestZip.GetUInt32(missing, eocd + 16) - 16);
        ExpectZipError(() => StrictZip.Read(missing, MaxEntries), "zip_invalid");
    }

    [Fact]
    public void RefusesNonUtf8Names()
    {
        var zip = TestZip.Write(new TestEntry("a.txt", "x") { Compress = false });
        var cd = TestZip.CentralOffsets(zip)[0];
        var legacy = Copy(zip);
        TestZip.PutUInt16(legacy, cd + 8, 0); // clear the UTF-8 flag in the central directory
        legacy[cd + 46] = 0xe9; // and use a byte from a legacy code page
        ExpectZipError(() => StrictZip.Read(legacy, MaxEntries), "name_not_utf8");
        var invalid = Copy(zip);
        invalid[cd + 46] = 0xff; // flagged UTF-8, but not UTF-8
        ExpectZipError(() => StrictZip.Read(invalid, MaxEntries), "name_not_utf8");
    }

    [Fact]
    public void LimitsTheNumberOfEntries()
    {
        var files = Enumerable.Range(0, 12).Select(i => new TestEntry($"f{i}.txt", i.ToString(CultureInfo.InvariantCulture))).ToArray();
        var zip = TestZip.Write(files);
        ExpectZipError(() => StrictZip.Read(zip, 10), "too_many_entries");
        Assert.Equal(12, StrictZip.Read(zip, 12).Count);
    }
}
