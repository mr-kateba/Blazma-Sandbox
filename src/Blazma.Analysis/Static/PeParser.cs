using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection.PortableExecutable;
using System.Text;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Static;

/// <summary>
/// Reads PE metadata from a byte buffer without loading or executing anything. Every
/// offset read from the file is bounds-checked; malformed input produces warnings, never
/// exceptions that escape.
/// </summary>
public static class PeParser
{
    private const int MaxImportLibraries = 512;
    private const int MaxFunctionsPerLibrary = 4096;
    private const int MaxTotalImports = 20_000;
    private const int MaxExports = 4096;
    private const int MaxNameLength = 512;
    private const int MaxResourceLeaves = 10_000;
    private const int ResourceTypeVersion = 16;

    public static PeInfo? TryParse(byte[] image, List<string> warnings)
    {
        if (image.Length < 64 || image[0] != 'M' || image[1] != 'Z') return null;
        try
        {
            using var reader = new PEReader(ImmutableArray.Create(image));
            var headers = reader.PEHeaders;
            var coff = headers.CoffHeader;
            var pe = headers.PEHeader;
            if (pe is null)
            {
                warnings.Add("The file has an MZ header but no optional PE header.");
                return null;
            }

            var view = new ImageView(image, headers.SectionHeaders);
            var is64 = pe.Magic == PEMagic.PE32Plus;

            var sections = headers.SectionHeaders.Select(s =>
            {
                var start = Math.Clamp(s.PointerToRawData, 0, image.Length);
                var len = Math.Clamp(s.SizeOfRawData, 0, image.Length - start);
                return new PeSection(
                    s.Name,
                    (uint)s.VirtualSize,
                    (uint)s.SizeOfRawData,
                    Math.Round(Entropy.Of(image.AsSpan(start, len)), 3),
                    s.SectionCharacteristics.HasFlag(SectionCharacteristics.MemExecute),
                    s.SectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite));
            }).ToList();

            var imports = SafeRun(() => ReadImports(view, pe.ImportTableDirectory, is64), warnings, "imports") ?? [];
            var exports = SafeRun(() => ReadExports(view, pe.ExportTableDirectory), warnings, "exports") ?? [];
            var (resourceCount, versionBlock) = SafeRun(() => ReadResources(view, pe.ResourceTableDirectory), warnings, "resources");
            var version = versionBlock is null ? new Dictionary<string, string>() : SafeRun(() => ReadVersionInfo(versionBlock), warnings, "version information") ?? [];

            DateTimeOffset? timestamp = coff.TimeDateStamp > 0
                ? DateTimeOffset.FromUnixTimeSeconds((uint)coff.TimeDateStamp)
                : null;

            var lastSectionEnd = headers.SectionHeaders.Length == 0 ? 0L :
                headers.SectionHeaders.Max(s => (long)s.PointerToRawData + s.SizeOfRawData);
            var certTable = pe.CertificateTableDirectory;
            var overlayEnd = certTable.Size > 0 && certTable.RelativeVirtualAddress > 0 ? certTable.RelativeVirtualAddress : image.Length;
            var hasOverlay = overlayEnd - lastSectionEnd > 512;

            return new PeInfo
            {
                Machine = coff.Machine switch
                {
                    Machine.Amd64 => "x64",
                    Machine.I386 => "x86",
                    Machine.Arm64 => "ARM64",
                    Machine.Arm or Machine.ArmThumb2 or Machine.Thumb => "ARM",
                    _ => coff.Machine.ToString(),
                },
                Is64Bit = is64,
                IsDll = coff.Characteristics.HasFlag(Characteristics.Dll),
                Subsystem = pe.Subsystem switch
                {
                    Subsystem.WindowsGui => "Windows GUI",
                    Subsystem.WindowsCui => "Windows Console",
                    Subsystem.Native => "Native",
                    Subsystem.EfiApplication or Subsystem.EfiBootServiceDriver or Subsystem.EfiRuntimeDriver => "EFI",
                    _ => pe.Subsystem.ToString(),
                },
                IsDotNet = headers.CorHeader is not null,
                CompileTimestamp = timestamp,
                Sections = sections,
                Imports = imports,
                Exports = exports,
                ResourceCount = resourceCount,
                VersionInfo = version,
                HasOverlay = hasOverlay,
            };
        }
        catch (BadImageFormatException ex)
        {
            warnings.Add($"Malformed PE headers: {ex.Message}");
            return null;
        }
    }

    public static bool HasSignatureDirectory(byte[] image)
    {
        try
        {
            using var reader = new PEReader(ImmutableArray.Create(image));
            var dir = reader.PEHeaders.PEHeader?.CertificateTableDirectory;
            return dir is { Size: > 0, RelativeVirtualAddress: > 0 };
        }
        catch (BadImageFormatException)
        {
            return false;
        }
    }

    private static T? SafeRun<T>(Func<T> read, List<string> warnings, string what)
    {
        try
        {
            return read();
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or IndexOutOfRangeException or InvalidDataException or BadImageFormatException)
        {
            warnings.Add($"Could not read {what}: the table is malformed.");
            return default;
        }
    }

    private static List<PeImport> ReadImports(ImageView view, DirectoryEntry dir, bool is64)
    {
        var result = new List<PeImport>();
        if (dir.Size == 0 || !view.TryOffset(dir.RelativeVirtualAddress, out var offset)) return result;
        var total = 0;
        for (var i = 0; i < MaxImportLibraries; i++)
        {
            var d = offset + i * 20;
            if (!view.Has(d, 20)) break;
            var originalFirstThunk = view.U32(d);
            var nameRva = view.U32(d + 12);
            var firstThunk = view.U32(d + 16);
            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;

            var library = view.AsciiAtRva(nameRva) ?? "?";
            var functions = new List<string>();
            var thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            if (view.TryOffset((int)thunkRva, out var thunk))
            {
                var size = is64 ? 8 : 4;
                for (var j = 0; j < MaxFunctionsPerLibrary && total < MaxTotalImports; j++)
                {
                    var t = thunk + j * size;
                    if (!view.Has(t, size)) break;
                    var value = is64 ? view.U64(t) : view.U32(t);
                    if (value == 0) break;
                    var ordinalFlag = is64 ? 1UL << 63 : 1UL << 31;
                    if ((value & ordinalFlag) != 0)
                    {
                        functions.Add($"#{value & 0xFFFF}");
                    }
                    else
                    {
                        var name = view.AsciiAtRva((uint)(value & 0x7FFFFFFF), skip: 2);
                        if (name is not null) functions.Add(name);
                    }
                    total++;
                }
            }
            result.Add(new PeImport(library, functions));
        }
        return result;
    }

    private static List<string> ReadExports(ImageView view, DirectoryEntry dir)
    {
        var result = new List<string>();
        if (dir.Size == 0 || !view.TryOffset(dir.RelativeVirtualAddress, out var d) || !view.Has(d, 40)) return result;
        var numberOfNames = (int)Math.Min(view.U32(d + 24), MaxExports);
        var namesRva = view.U32(d + 32);
        if (!view.TryOffset((int)namesRva, out var names)) return result;
        for (var i = 0; i < numberOfNames; i++)
        {
            if (!view.Has(names + i * 4, 4)) break;
            var name = view.AsciiAtRva(view.U32(names + i * 4));
            if (name is not null) result.Add(name);
        }
        return result;
    }

    private static (int Count, byte[]? Version) ReadResources(ImageView view, DirectoryEntry dir)
    {
        if (dir.Size == 0 || !view.TryOffset(dir.RelativeVirtualAddress, out var root)) return (0, null);
        var count = 0;
        byte[]? version = null;

        void Walk(int dirOffset, int depth, int typeId)
        {
            if (depth > 3 || !view.Has(dirOffset, 16) || count >= MaxResourceLeaves) return;
            var entries = view.U16(dirOffset + 12) + view.U16(dirOffset + 14);
            for (var i = 0; i < entries && count < MaxResourceLeaves; i++)
            {
                var e = dirOffset + 16 + i * 8;
                if (!view.Has(e, 8)) return;
                var nameOrId = view.U32(e);
                var data = view.U32(e + 4);
                var id = depth == 0 && (nameOrId & 0x80000000) == 0 ? (int)nameOrId : typeId;
                if ((data & 0x80000000) != 0)
                {
                    var sub = root + (int)(data & 0x7FFFFFFF);
                    if (sub > dirOffset) Walk(sub, depth + 1, id);
                }
                else
                {
                    count++;
                    var leaf = root + (int)data;
                    if (version is null && id == ResourceTypeVersion && view.Has(leaf, 16))
                    {
                        var rva = view.U32(leaf);
                        var size = (int)Math.Min(view.U32(leaf + 4), 64 * 1024);
                        if (view.TryOffset((int)rva, out var at) && view.Has(at, size))
                            version = view.Slice(at, size);
                    }
                }
            }
        }

        Walk(root, 0, 0);
        return (count, version);
    }

    /// <summary>Parses VS_VERSIONINFO and returns the StringFileInfo values of the first string table.</summary>
    private static Dictionary<string, string> ReadVersionInfo(byte[] block)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        ParseBlock(block, 0, block.Length, 0, values);
        return values;
    }

    private static void ParseBlock(byte[] data, int start, int limit, int depth, Dictionary<string, string> values)
    {
        if (depth > 4 || start + 6 > limit) return;
        int length = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(start));
        int valueLength = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(start + 2));
        int type = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(start + 4));
        if (length < 6) return;
        var end = Math.Min(start + length, limit);

        var keyStart = start + 6;
        var keyEnd = keyStart;
        while (keyEnd + 1 < end && (data[keyEnd] != 0 || data[keyEnd + 1] != 0)) keyEnd += 2;
        var key = Encoding.Unicode.GetString(data, keyStart, keyEnd - keyStart);
        var cursor = Align4(keyEnd + 2);

        if (depth == 3)
        {
            // A String entry: value length is in WORDs for text values.
            var bytes = type == 1 ? valueLength * 2 : valueLength;
            if (cursor + bytes <= end && bytes > 0)
            {
                var value = Encoding.Unicode.GetString(data, cursor, bytes).TrimEnd('\0').Trim();
                if (value.Length > 0 && values.Count < 32) values[key] = value.Length > MaxNameLength ? value[..MaxNameLength] : value;
            }
            return;
        }

        cursor = Align4(cursor + valueLength);
        // Only StringFileInfo carries strings; VarFileInfo is skipped.
        if (depth == 1 && key != "StringFileInfo") return;
        while (cursor + 6 <= end)
        {
            int childLength = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(cursor));
            if (childLength < 6) break;
            ParseBlock(data, cursor, end, depth + 1, values);
            cursor = Align4(cursor + childLength);
            if (depth == 1 && values.Count > 0) break; // first string table is enough
        }
    }

    private static int Align4(int value) => (value + 3) & ~3;

    /// <summary>Bounds-checked access to a PE image by file offset or RVA.</summary>
    private sealed class ImageView(byte[] image, ImmutableArray<SectionHeader> sections)
    {
        public bool Has(int offset, int length) => offset >= 0 && length >= 0 && (long)offset + length <= image.Length;

        public bool TryOffset(int rva, out int offset)
        {
            offset = -1;
            if (rva <= 0) return false;
            foreach (var s in sections)
            {
                var size = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
                {
                    var o = (long)rva - s.VirtualAddress + s.PointerToRawData;
                    if (o < 0 || o >= image.Length) return false;
                    offset = (int)o;
                    return true;
                }
            }
            return false;
        }

        public uint U32(int offset) => BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(offset, 4));
        public ulong U64(int offset) => BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(offset, 8));
        public int U16(int offset) => BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(offset, 2));
        public byte[] Slice(int offset, int length) => image.AsSpan(offset, length).ToArray();

        public string? AsciiAtRva(uint rva, int skip = 0)
        {
            if (!TryOffset((int)rva, out var o)) return null;
            o += skip;
            if (!Has(o, 1)) return null;
            var end = o;
            while (end < image.Length && image[end] != 0 && end - o < MaxNameLength) end++;
            if (end == o) return null;
            var s = Encoding.ASCII.GetString(image, o, end - o);
            return s.All(c => c >= 0x20 && c < 0x7F) ? s : null;
        }
    }
}
