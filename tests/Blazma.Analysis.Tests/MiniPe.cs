using System.Buffers.Binary;
using System.Text;

namespace Blazma.Analysis.Tests;

/// <summary>
/// Builds a tiny, valid, non-runnable PE image with a chosen import table, so import-related
/// code can be tested without shipping binaries. Functions are names, or "#N" for an ordinal.
/// </summary>
internal static class MiniPe
{
    private const int FileAlignment = 0x200;
    private const int SectionAlignment = 0x1000;
    private const int SectionRva = 0x1000;
    private const int SectionRaw = 0x200;

    public static byte[] Build(bool is64, params (string Library, string[] Functions)[] imports) => Build(is64, imports, []);

    public static byte[] Build(bool is64, (string Library, string[] Functions)[] imports, byte[] extraData)
    {
        var thunkSize = is64 ? 8 : 4;
        var section = new List<byte>();
        var descriptorsSize = (imports.Length + 1) * 20;
        section.AddRange(new byte[descriptorsSize]);

        int Here() => SectionRva + section.Count;
        void Pad() { while (section.Count % 8 != 0) section.Add(0); }

        var ilt = new int[imports.Length];
        var iat = new int[imports.Length];
        var nameRvas = new int[imports.Length];
        var thunkValues = new List<ulong>[imports.Length];

        // Hint/name entries and DLL names first, so thunk values are known.
        for (var i = 0; i < imports.Length; i++)
        {
            thunkValues[i] = [];
            foreach (var f in imports[i].Functions)
            {
                if (f.StartsWith('#'))
                {
                    var ord = ulong.Parse(f.AsSpan(1), System.Globalization.CultureInfo.InvariantCulture);
                    thunkValues[i].Add((is64 ? 1UL << 63 : 1UL << 31) | ord);
                }
                else
                {
                    Pad();
                    thunkValues[i].Add((ulong)Here());
                    section.Add(0); section.Add(0); // hint
                    section.AddRange(Encoding.ASCII.GetBytes(f));
                    section.Add(0);
                }
            }
            Pad();
            nameRvas[i] = Here();
            section.AddRange(Encoding.ASCII.GetBytes(imports[i].Library));
            section.Add(0);
        }

        foreach (var table in new[] { ilt, iat })
        {
            for (var i = 0; i < imports.Length; i++)
            {
                Pad();
                table[i] = Here();
                foreach (var v in thunkValues[i].Append(0UL))
                {
                    var b = new byte[thunkSize];
                    if (is64) BinaryPrimitives.WriteUInt64LittleEndian(b, v); else BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)v);
                    section.AddRange(b);
                }
            }
        }
        Pad();
        section.AddRange(extraData);

        var raw = section.ToArray();
        for (var i = 0; i < imports.Length; i++)
        {
            var d = raw.AsSpan(i * 20, 20);
            BinaryPrimitives.WriteInt32LittleEndian(d, ilt[i]);
            BinaryPrimitives.WriteInt32LittleEndian(d[12..], nameRvas[i]);
            BinaryPrimitives.WriteInt32LittleEndian(d[16..], iat[i]);
        }

        var rawSize = Align(raw.Length, FileAlignment);
        var virtualSize = raw.Length;
        var image = new byte[SectionRaw + rawSize];
        raw.CopyTo(image, SectionRaw);

        image[0] = (byte)'M'; image[1] = (byte)'Z';
        const int peOffset = 0x40;
        BinaryPrimitives.WriteInt32LittleEndian(image.AsSpan(0x3C), peOffset);
        "PE\0\0"u8.CopyTo(image.AsSpan(peOffset));
        var coff = peOffset + 4;
        var optionalSize = is64 ? 240 : 224;
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(coff), is64 ? (ushort)0x8664 : (ushort)0x14C);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(coff + 2), 1); // sections
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(coff + 16), (ushort)optionalSize);
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(coff + 18), is64 ? (ushort)0x0022 : (ushort)0x0102); // executable

        var opt = coff + 20;
        var o = image.AsSpan(opt);
        BinaryPrimitives.WriteUInt16LittleEndian(o, is64 ? (ushort)0x20B : (ushort)0x10B);
        BinaryPrimitives.WriteInt32LittleEndian(o[16..], SectionRva); // entry point
        if (is64) BinaryPrimitives.WriteUInt64LittleEndian(o[24..], 0x140000000); else BinaryPrimitives.WriteUInt32LittleEndian(o[28..], 0x400000);
        BinaryPrimitives.WriteInt32LittleEndian(o[32..], SectionAlignment);
        BinaryPrimitives.WriteInt32LittleEndian(o[36..], FileAlignment);
        BinaryPrimitives.WriteUInt16LittleEndian(o[40..], 6); // OS version
        BinaryPrimitives.WriteUInt16LittleEndian(o[48..], 6); // subsystem version
        BinaryPrimitives.WriteInt32LittleEndian(o[56..], SectionRva + Align(virtualSize, SectionAlignment)); // SizeOfImage
        BinaryPrimitives.WriteInt32LittleEndian(o[60..], SectionRaw); // SizeOfHeaders
        BinaryPrimitives.WriteUInt16LittleEndian(o[68..], 3); // console
        var dirs = is64 ? 112 : 96;
        BinaryPrimitives.WriteInt32LittleEndian(o[(dirs - 4)..], 16); // NumberOfRvaAndSizes
        BinaryPrimitives.WriteInt32LittleEndian(o[(dirs + 8)..], SectionRva); // import directory
        BinaryPrimitives.WriteInt32LittleEndian(o[(dirs + 12)..], descriptorsSize);

        var sh = image.AsSpan(opt + optionalSize);
        ".idata\0\0"u8.CopyTo(sh);
        BinaryPrimitives.WriteInt32LittleEndian(sh[8..], virtualSize);
        BinaryPrimitives.WriteInt32LittleEndian(sh[12..], SectionRva);
        BinaryPrimitives.WriteInt32LittleEndian(sh[16..], rawSize);
        BinaryPrimitives.WriteInt32LittleEndian(sh[20..], SectionRaw);
        BinaryPrimitives.WriteUInt32LittleEndian(sh[36..], 0xC0000040); // initialised data, read, write
        return image;
    }

    private static int Align(int value, int alignment) => (value + alignment - 1) / alignment * alignment;
}
