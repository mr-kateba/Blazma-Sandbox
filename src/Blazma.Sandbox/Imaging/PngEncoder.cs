using System.Buffers.Binary;
using System.IO.Compression;

namespace Blazma.Sandbox.Imaging;

/// <summary>
/// Minimal PNG writer for pixels the host already holds in memory (8-bit RGB, no
/// interlacing). Writing PNG ourselves means screenshots from the sandbox never pass
/// through a third-party image decoder on the host.
/// </summary>
public static class PngEncoder
{
    private static ReadOnlySpan<byte> Signature => [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    /// <summary>Encodes 32-bit BGRA pixels (top row first). Alpha is dropped: screenshots are opaque.</summary>
    public static byte[] EncodeBgra(int width, int height, ReadOnlySpan<byte> bgra)
    {
        if (width <= 0 || height <= 0) throw new ArgumentOutOfRangeException(nameof(width));
        if (bgra.Length != width * height * 4) throw new ArgumentException("Pixel buffer does not match the size.", nameof(bgra));

        var rowBytes = width * 3 + 1;
        var raw = new byte[rowBytes * height];
        for (var y = 0; y < height; y++)
        {
            var dst = y * rowBytes;
            raw[dst++] = 0; // filter: none
            var src = y * width * 4;
            for (var x = 0; x < width; x++, src += 4)
            {
                raw[dst++] = bgra[src + 2];
                raw[dst++] = bgra[src + 1];
                raw[dst++] = bgra[src];
            }
        }

        using var output = new MemoryStream();
        output.Write(Signature);
        Span<byte> ihdr = stackalloc byte[13];
        BinaryPrimitives.WriteInt32BigEndian(ihdr, width);
        BinaryPrimitives.WriteInt32BigEndian(ihdr[4..], height);
        ihdr[8] = 8;  // bit depth
        ihdr[9] = 2;  // colour type: truecolour
        ihdr[10] = 0; // compression
        ihdr[11] = 0; // filter
        ihdr[12] = 0; // interlace
        WriteChunk(output, "IHDR"u8, ihdr);

        using (var compressed = new MemoryStream())
        {
            using (var z = new ZLibStream(compressed, CompressionLevel.Optimal, leaveOpen: true)) z.Write(raw);
            WriteChunk(output, "IDAT"u8, compressed.ToArray());
        }
        WriteChunk(output, "IEND"u8, []);
        return output.ToArray();
    }

    private static void WriteChunk(Stream output, ReadOnlySpan<byte> type, ReadOnlySpan<byte> data)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, data.Length);
        output.Write(length);
        output.Write(type);
        output.Write(data);
        var crc = Crc32(Crc32(0xFFFFFFFFu, type), data) ^ 0xFFFFFFFFu;
        Span<byte> sum = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(sum, crc);
        output.Write(sum);
    }

    private static readonly uint[] CrcTable = BuildCrcTable();

    private static uint[] BuildCrcTable()
    {
        var table = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            var c = n;
            for (var k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[n] = c;
        }
        return table;
    }

    private static uint Crc32(uint crc, ReadOnlySpan<byte> data)
    {
        foreach (var b in data) crc = CrcTable[(crc ^ b) & 0xFF] ^ (crc >> 8);
        return crc;
    }
}
