using System.Buffers.Binary;
using System.IO.Compression;

namespace Blazma.Contracts;

/// <summary>
/// The screenshot format between agent and host: <c>"BLZF"</c>, u16 width, u16 height,
/// u32 milliseconds since the sample started, then gzip-compressed 32-bit BGRA pixels,
/// top row first. Deliberately not an image file format: the host never runs an image
/// decoder on data that came out of the sandbox; it only inflates bytes into a buffer of
/// exactly the size the header announces and encodes the PNG itself.
/// </summary>
public static class RawFrame
{
    private const int HeaderBytes = 12;

    public static byte[] Encode(int width, int height, long relativeMs, ReadOnlySpan<byte> bgra)
    {
        if (width <= 0 || height <= 0 || width > ushort.MaxValue || height > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(width));
        if (bgra.Length != width * height * 4) throw new ArgumentException("Pixel buffer does not match the size.", nameof(bgra));
        using var output = new MemoryStream();
        Span<byte> header = stackalloc byte[HeaderBytes];
        Protocol.ScreenshotMagic.CopyTo(header);
        BinaryPrimitives.WriteUInt16LittleEndian(header[4..], (ushort)width);
        BinaryPrimitives.WriteUInt16LittleEndian(header[6..], (ushort)height);
        BinaryPrimitives.WriteUInt32LittleEndian(header[8..], (uint)Math.Clamp(relativeMs, 0, uint.MaxValue));
        output.Write(header);
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true)) gzip.Write(bgra);
        return output.ToArray();
    }

    /// <summary>Decodes a frame within the host's limits. Returns false for anything malformed or oversized.</summary>
    public static bool TryDecode(ReadOnlySpan<byte> data, int maxWidth, int maxHeight, out int width, out int height, out long relativeMs, out byte[] bgra)
    {
        width = height = 0;
        relativeMs = 0;
        bgra = [];
        if (data.Length < HeaderBytes || !data[..4].SequenceEqual(Protocol.ScreenshotMagic)) return false;
        width = BinaryPrimitives.ReadUInt16LittleEndian(data[4..]);
        height = BinaryPrimitives.ReadUInt16LittleEndian(data[6..]);
        relativeMs = BinaryPrimitives.ReadUInt32LittleEndian(data[8..]);
        if (width < 1 || height < 1 || width > maxWidth || height > maxHeight) return false;

        var expected = width * height * 4;
        var pixels = new byte[expected];
        try
        {
            using var input = new GZipStream(new MemoryStream(data[HeaderBytes..].ToArray()), CompressionMode.Decompress);
            var read = 0;
            while (read < expected)
            {
                var n = input.Read(pixels, read, expected - read);
                if (n == 0) return false;
                read += n;
            }
            // Anything after the announced pixels means the header lied: reject instead of guessing.
            if (input.ReadByte() != -1) return false;
        }
        catch (InvalidDataException)
        {
            return false;
        }
        bgra = pixels;
        return true;
    }
}
