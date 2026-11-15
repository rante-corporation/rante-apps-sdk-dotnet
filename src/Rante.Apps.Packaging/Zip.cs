using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Rante.Apps.Packaging;

/// <summary>A ZIP structure problem, with a stable code.</summary>
internal sealed class ZipFormatException : Exception
{
    public ZipFormatException(string code, string message, string? path = null)
        : base(message)
    {
        Code = code;
        Path = path;
    }

    public string Code { get; }

    public string? Path { get; }
}

/// <summary>One entry of the central directory, checked against its local header.</summary>
internal sealed class ZipEntry
{
    public required string Name { get; init; }

    public required byte[] NameBytes { get; init; }

    public required int Flags { get; init; }

    public required int Method { get; init; }

    public required uint Crc32 { get; init; }

    public required long CompressedSize { get; init; }

    public required long UncompressedSize { get; init; }

    public required int VersionMadeBy { get; init; }

    public required uint ExternalAttributes { get; init; }

    public required long LocalHeaderOffset { get; init; }

    public long DataOffset { get; set; }

    public long DataEnd { get; set; }

    public long RecordEnd { get; set; }
}

/// <summary>
/// A strict ZIP reader, the C# twin of rante-apps-sdk's packages/cli/lib/zip.js. It refuses ZIP64, split archives,
/// encryption, compression methods other than stored and deflate, entries whose local header disagrees with the
/// central directory, overlapping entries, data before the first entry and names that are not UTF-8. Entry data is
/// inflated with a hard cap at the declared size, then checked against that size and the CRC-32.
/// </summary>
internal static class StrictZip
{
    private const uint SigLocal = 0x04034b50;
    private const uint SigCentral = 0x02014b50;
    private const uint SigEnd = 0x06054b50;
    private const uint SigZip64Locator = 0x07064b50;
    private const uint SigDataDescriptor = 0x08074b50;
    private const int FlagEncrypted = 0x0001;
    private const int FlagDataDescriptor = 0x0008;
    private const int FlagStrongEncryption = 0x0040;
    private const int FlagUtf8 = 0x0800;
    private const int FlagMaskedHeaders = 0x2000;
    public const int MethodStored = 0;
    public const int MethodDeflate = 8;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private static uint U32(ReadOnlySpan<byte> buffer, long offset) => BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice((int)offset, 4));

    private static int U16(ReadOnlySpan<byte> buffer, long offset) => BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice((int)offset, 2));

    private static string DecodeName(ReadOnlySpan<byte> bytes, int flags)
    {
        if ((flags & FlagUtf8) != 0)
        {
            try
            {
                return StrictUtf8.GetString(bytes);
            }
            catch (DecoderFallbackException)
            {
                throw new ZipFormatException("name_not_utf8", "An entry name is marked UTF-8 but is not valid UTF-8.");
            }
        }

        foreach (var b in bytes)
        {
            if (b >= 0x80)
            {
                throw new ZipFormatException("name_not_utf8",
                    "An entry name uses a legacy code page. Repack with UTF-8 names (rante pack, or any current zip tool).");
            }
        }

        return Encoding.ASCII.GetString(bytes);
    }

    /// <summary>Reads the archive structure. No entry data is inflated.</summary>
    public static List<ZipEntry> Read(ReadOnlySpan<byte> buf, int maxEntries, int maxCommentBytes = 1024)
    {
        if (buf.Length < 22)
        {
            throw new ZipFormatException("zip_invalid", "The file is too short to be a ZIP archive.");
        }

        long eocd = -1;
        var lowest = Math.Max(0, buf.Length - 22 - 0xffff);
        for (long p = buf.Length - 22; p >= lowest; p--)
        {
            if (U32(buf, p) == SigEnd && p + 22 + U16(buf, p + 20) == buf.Length)
            {
                eocd = p;
                break;
            }
        }

        if (eocd < 0)
        {
            throw new ZipFormatException("zip_invalid", "The end of central directory record is missing: the archive is damaged or truncated.");
        }

        var diskNumber = U16(buf, eocd + 4);
        var centralDisk = U16(buf, eocd + 6);
        var entriesOnDisk = U16(buf, eocd + 8);
        var entryCount = U16(buf, eocd + 10);
        long centralSize = U32(buf, eocd + 12);
        long centralOffset = U32(buf, eocd + 16);
        var commentLength = U16(buf, eocd + 20);

        if (entryCount == 0xffff || centralSize == 0xffffffffL || centralOffset == 0xffffffffL ||
            (eocd >= 20 && U32(buf, eocd - 20) == SigZip64Locator))
        {
            throw new ZipFormatException("zip64_not_supported", "ZIP64 archives are not supported. Packages are at most 50 MiB.");
        }

        if (diskNumber != 0 || centralDisk != 0 || entriesOnDisk != entryCount)
        {
            throw new ZipFormatException("zip_invalid", "Split (multi-volume) archives are not supported.");
        }

        if (commentLength > maxCommentBytes)
        {
            throw new ZipFormatException("zip_invalid", $"The archive comment is {commentLength} bytes; the limit is {maxCommentBytes}.");
        }

        if (centralOffset + centralSize != eocd)
        {
            throw new ZipFormatException("zip_invalid", "The central directory does not end where the end record starts.");
        }

        if (entryCount > maxEntries)
        {
            throw new ZipFormatException("too_many_entries", $"The archive has {entryCount} entries; the limit is {maxEntries}.");
        }

        var entries = new List<ZipEntry>(entryCount);
        var p2 = centralOffset;
        for (var n = 0; n < entryCount; n++)
        {
            if (p2 + 46 > eocd || U32(buf, p2) != SigCentral)
            {
                throw new ZipFormatException("zip_invalid", $"Central directory entry {n + 1} is damaged.");
            }

            var versionMadeBy = U16(buf, p2 + 4);
            var flags = U16(buf, p2 + 8);
            var method = U16(buf, p2 + 10);
            var crc = U32(buf, p2 + 16);
            long compressedSize = U32(buf, p2 + 20);
            long uncompressedSize = U32(buf, p2 + 24);
            var nameLength = U16(buf, p2 + 28);
            var extraLength = U16(buf, p2 + 30);
            var entryCommentLength = U16(buf, p2 + 32);
            var diskStart = U16(buf, p2 + 34);
            var externalAttributes = U32(buf, p2 + 38);
            long localHeaderOffset = U32(buf, p2 + 42);
            var next = p2 + 46 + nameLength + extraLength + entryCommentLength;
            if (next > eocd)
            {
                throw new ZipFormatException("zip_invalid", $"Central directory entry {n + 1} runs past the end record.");
            }

            var nameBytes = buf.Slice((int)(p2 + 46), nameLength).ToArray();
            var name = DecodeName(nameBytes, flags);
            if (compressedSize == 0xffffffffL || uncompressedSize == 0xffffffffL || localHeaderOffset == 0xffffffffL)
            {
                throw new ZipFormatException("zip64_not_supported", $"\"{name}\" uses ZIP64 sizes, which are not supported.", name);
            }

            if (diskStart != 0)
            {
                throw new ZipFormatException("zip_invalid", $"\"{name}\" claims to start on another disk.", name);
            }

            if ((flags & (FlagEncrypted | FlagStrongEncryption | FlagMaskedHeaders)) != 0)
            {
                throw new ZipFormatException("zip_encrypted", $"\"{name}\" is encrypted. Packages must not be encrypted.", name);
            }

            if (method != MethodStored && method != MethodDeflate)
            {
                throw new ZipFormatException("zip_method_unsupported",
                    $"\"{name}\" uses compression method {method}; only stored (0) and deflate (8) are supported.", name);
            }

            entries.Add(new ZipEntry
            {
                Name = name,
                NameBytes = nameBytes,
                Flags = flags,
                Method = method,
                Crc32 = crc,
                CompressedSize = compressedSize,
                UncompressedSize = uncompressedSize,
                VersionMadeBy = versionMadeBy,
                ExternalAttributes = externalAttributes,
                LocalHeaderOffset = localHeaderOffset,
            });
            p2 = next;
        }

        if (p2 != eocd)
        {
            throw new ZipFormatException("zip_invalid", "The central directory has unexpected trailing data.");
        }

        foreach (var e in entries)
        {
            var lh = e.LocalHeaderOffset;
            if (lh + 30 > centralOffset || U32(buf, lh) != SigLocal)
            {
                throw new ZipFormatException("zip_entry_mismatch", $"The local header of \"{e.Name}\" is missing.", e.Name);
            }

            var localFlags = U16(buf, lh + 6);
            var localMethod = U16(buf, lh + 8);
            var localNameLength = U16(buf, lh + 26);
            var localExtraLength = U16(buf, lh + 28);
            if (lh + 30 + localNameLength + localExtraLength > centralOffset)
            {
                throw new ZipFormatException("zip_entry_mismatch", $"The local header of \"{e.Name}\" runs into the central directory.", e.Name);
            }

            if (!buf.Slice((int)(lh + 30), localNameLength).SequenceEqual(e.NameBytes))
            {
                throw new ZipFormatException("zip_entry_mismatch",
                    $"The local header of \"{e.Name}\" names a different file. The archive is damaged or crafted.", e.Name);
            }

            if (localMethod != e.Method || (localFlags & FlagEncrypted) != (e.Flags & FlagEncrypted) ||
                (localFlags & FlagDataDescriptor) != (e.Flags & FlagDataDescriptor))
            {
                throw new ZipFormatException("zip_entry_mismatch", $"The local header of \"{e.Name}\" disagrees with the central directory.", e.Name);
            }

            if ((localFlags & FlagDataDescriptor) == 0 &&
                (U32(buf, lh + 14) != e.Crc32 || U32(buf, lh + 18) != e.CompressedSize || U32(buf, lh + 22) != e.UncompressedSize))
            {
                throw new ZipFormatException("zip_entry_mismatch",
                    $"The local header of \"{e.Name}\" has a different size or CRC than the central directory.", e.Name);
            }

            e.DataOffset = lh + 30 + localNameLength + localExtraLength;
            e.DataEnd = e.DataOffset + e.CompressedSize;
            if (e.DataEnd > centralOffset)
            {
                throw new ZipFormatException("zip_invalid", $"The data of \"{e.Name}\" runs into the central directory.", e.Name);
            }

            e.RecordEnd = (localFlags & FlagDataDescriptor) != 0 ? ReadDataDescriptor(buf, e, centralOffset) : e.DataEnd;
        }

        var byOffset = entries.OrderBy(e => e.LocalHeaderOffset).ToList();
        if (byOffset.Count > 0 && byOffset[0].LocalHeaderOffset != 0)
        {
            throw new ZipFormatException("zip_invalid", "The archive has data before its first entry.");
        }

        for (var i = 1; i < byOffset.Count; i++)
        {
            if (byOffset[i].LocalHeaderOffset < byOffset[i - 1].RecordEnd)
            {
                throw new ZipFormatException("zip_entry_overlap",
                    $"\"{byOffset[i].Name}\" overlaps \"{byOffset[i - 1].Name}\". Overlapping entries are a zip-bomb technique.", byOffset[i].Name);
            }
        }

        return entries;
    }

    private static long ReadDataDescriptor(ReadOnlySpan<byte> buf, ZipEntry e, long limit)
    {
        var q = e.DataEnd;
        if (q + 4 <= limit && U32(buf, q) == SigDataDescriptor)
        {
            q += 4;
        }

        if (q + 12 > limit)
        {
            throw new ZipFormatException("zip_invalid", $"The data descriptor of \"{e.Name}\" is missing.", e.Name);
        }

        if (U32(buf, q) != e.Crc32 || U32(buf, q + 4) != e.CompressedSize || U32(buf, q + 8) != e.UncompressedSize)
        {
            throw new ZipFormatException("zip_entry_mismatch", $"The data descriptor of \"{e.Name}\" disagrees with the central directory.", e.Name);
        }

        return q + 12;
    }

    /// <summary>An entry's bytes, inflated with a hard cap at the declared size, then size- and CRC-checked.</summary>
    public static byte[] ReadData(byte[] buf, ZipEntry entry)
    {
        var raw = new ReadOnlySpan<byte>(buf, (int)entry.DataOffset, (int)entry.CompressedSize);
        byte[] data;
        if (entry.Method == MethodStored)
        {
            if (entry.CompressedSize != entry.UncompressedSize)
            {
                throw new ZipFormatException("zip_size_mismatch", $"\"{entry.Name}\" is stored but its two sizes differ.", entry.Name);
            }

            data = raw.ToArray();
        }
        else
        {
            data = new byte[entry.UncompressedSize];
            try
            {
                using var input = new MemoryStream(buf, (int)entry.DataOffset, (int)entry.CompressedSize, writable: false);
                using var inflater = new DeflateStream(input, CompressionMode.Decompress);
                var read = 0;
                while (read < data.Length)
                {
                    var n = inflater.Read(data, read, data.Length - read);
                    if (n == 0)
                    {
                        break;
                    }

                    read += n;
                }

                if (read != data.Length)
                {
                    throw new ZipFormatException("zip_size_mismatch",
                        $"\"{entry.Name}\" is {read} bytes, not the declared {entry.UncompressedSize}.", entry.Name);
                }

                Span<byte> probe = stackalloc byte[1];
                if (inflater.Read(probe) != 0)
                {
                    throw new ZipFormatException("zip_size_mismatch",
                        $"\"{entry.Name}\" inflates to more than its declared {entry.UncompressedSize} bytes.", entry.Name);
                }
            }
            catch (InvalidDataException)
            {
                throw new ZipFormatException("zip_invalid", $"\"{entry.Name}\" has damaged compressed data.", entry.Name);
            }
        }

        if (Crc32.Compute(data) != entry.Crc32)
        {
            throw new ZipFormatException("zip_crc_mismatch", $"\"{entry.Name}\" fails its CRC-32 check: the archive is damaged.", entry.Name);
        }

        return data;
    }
}

/// <summary>CRC-32 (IEEE 802.3), the checksum ZIP stores for every entry.</summary>
internal static class Crc32
{
    private static readonly uint[] Table = BuildTable();

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            var c = n;
            for (var k = 0; k < 8; k++)
            {
                c = (c & 1) != 0 ? 0xedb88320u ^ (c >> 1) : c >> 1;
            }

            table[n] = c;
        }

        return table;
    }

    public static uint Compute(ReadOnlySpan<byte> data)
    {
        var crc = 0xffffffffu;
        foreach (var b in data)
        {
            crc = Table[(crc ^ b) & 0xff] ^ (crc >> 8);
        }

        return crc ^ 0xffffffffu;
    }
}
