using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Rante.Apps.Packaging.Tests;

/// <summary>One entry for <see cref="TestZip.Write"/>.</summary>
public sealed record TestEntry(string Name, byte[] Data, bool Compress = true, int? VersionMadeBy = null, uint? ExternalAttributes = null)
{
    public TestEntry(string name, string text)
        : this(name, Encoding.UTF8.GetBytes(text))
    {
    }

    /// <summary>The CRC and sizes follow the data in a data descriptor (flag bit 3), as streaming zip tools write them.</summary>
    public bool DataDescriptor { get; init; }

    /// <summary>Whether the data descriptor starts with its optional signature.</summary>
    public bool DescriptorSignature { get; init; } = true;
}

/// <summary>
/// A ZIP writer for the tests, the twin of rante-apps-sdk's writeZip: UTF-8 names, fixed timestamps, deflate when it
/// helps. The other options of <see cref="TestEntry"/> exist so tests can build unusual archives.
/// </summary>
public static class TestZip
{
    private const ushort FlagUtf8 = 0x0800;
    private const ushort FlagDataDescriptor = 0x0008;

    public static byte[] Write(params TestEntry[] entries)
    {
        using var output = new MemoryStream();
        using var central = new MemoryStream();
        foreach (var entry in entries)
        {
            var name = Encoding.UTF8.GetBytes(entry.Name);
            var crc = Crc32.Compute(entry.Data);
            var method = 0;
            var payload = entry.Data;
            if (entry.Compress && entry.Data.Length > 0)
            {
                var deflated = Deflate(entry.Data);
                if (deflated.Length < entry.Data.Length)
                {
                    method = 8;
                    payload = deflated;
                }
            }

            var flags = (ushort)(FlagUtf8 | (entry.DataDescriptor ? FlagDataDescriptor : 0));
            var offset = (uint)output.Length;
            var local = new byte[30];
            PutUInt32(local, 0, 0x04034b50);
            PutUInt16(local, 4, 20);
            PutUInt16(local, 6, flags);
            PutUInt16(local, 8, (ushort)method);
            PutUInt16(local, 10, 0);
            PutUInt16(local, 12, 0x0021);
            if (!entry.DataDescriptor)
            {
                PutUInt32(local, 14, crc);
                PutUInt32(local, 18, (uint)payload.Length);
                PutUInt32(local, 22, (uint)entry.Data.Length);
            }

            PutUInt16(local, 26, (ushort)name.Length);
            PutUInt16(local, 28, 0);
            output.Write(local);
            output.Write(name);
            output.Write(payload);
            if (entry.DataDescriptor)
            {
                var descriptor = new byte[16];
                var at = 0;
                if (entry.DescriptorSignature)
                {
                    PutUInt32(descriptor, 0, 0x08074b50);
                    at = 4;
                }

                PutUInt32(descriptor, at, crc);
                PutUInt32(descriptor, at + 4, (uint)payload.Length);
                PutUInt32(descriptor, at + 8, (uint)entry.Data.Length);
                output.Write(descriptor.AsSpan(0, at + 12));
            }

            var header = new byte[46];
            PutUInt32(header, 0, 0x02014b50);
            PutUInt16(header, 4, (ushort)(entry.VersionMadeBy ?? 20));
            PutUInt16(header, 6, 20);
            PutUInt16(header, 8, flags);
            PutUInt16(header, 10, (ushort)method);
            PutUInt16(header, 12, 0);
            PutUInt16(header, 14, 0x0021);
            PutUInt32(header, 16, crc);
            PutUInt32(header, 20, (uint)payload.Length);
            PutUInt32(header, 24, (uint)entry.Data.Length);
            PutUInt16(header, 28, (ushort)name.Length);
            PutUInt32(header, 38, entry.ExternalAttributes ?? 0);
            PutUInt32(header, 42, offset);
            central.Write(header);
            central.Write(name);
        }

        var centralOffset = (uint)output.Length;
        var centralBytes = central.ToArray();
        output.Write(centralBytes);
        var end = new byte[22];
        PutUInt32(end, 0, 0x06054b50);
        PutUInt16(end, 8, (ushort)entries.Length);
        PutUInt16(end, 10, (ushort)entries.Length);
        PutUInt32(end, 12, (uint)centralBytes.Length);
        PutUInt32(end, 16, centralOffset);
        output.Write(end);
        return output.ToArray();
    }

    public static byte[] Deflate(byte[] data)
    {
        using var output = new MemoryStream();
        using (var deflater = new DeflateStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            deflater.Write(data);
        }

        return output.ToArray();
    }

    /// <summary>The offsets of the central directory entries of an archive.</summary>
    public static List<int> CentralOffsets(byte[] zip)
    {
        var eocd = zip.Length - 22;
        var p = (int)GetUInt32(zip, eocd + 16);
        var offsets = new List<int>();
        while (p < eocd)
        {
            offsets.Add(p);
            p += 46 + GetUInt16(zip, p + 28) + GetUInt16(zip, p + 30) + GetUInt16(zip, p + 32);
        }

        return offsets;
    }

    public static void PutUInt32(byte[] zip, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(zip.AsSpan(offset), value);

    public static void PutUInt16(byte[] zip, int offset, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(zip.AsSpan(offset), value);

    public static uint GetUInt32(byte[] zip, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(offset));

    public static int GetUInt16(byte[] zip, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(offset));
}
