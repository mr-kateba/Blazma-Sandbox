using System.Collections.Immutable;
using System.Reflection.PortableExecutable;
using Blazma.Analysis.Static;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Yara;

/// <summary>
/// What the YARA <c>pe</c> module knows about the scanned data. Built once per scan, only when a
/// rule uses the module, from the same bounds-checked readers as static analysis. Data that is not
/// a PE gives null, and every <c>pe.*</c> value is then undefined (false), as in YARA.
/// </summary>
internal sealed class PeModuleData
{
    /// <summary>Larger buffers are not parsed for the module (static analysis has its own limits).</summary>
    public const int MaxBytes = 256 * 1024 * 1024;

    public required long Machine { get; init; }
    public required long NumberOfSections { get; init; }
    public required long Timestamp { get; init; }
    public required long PointerToSymbolTable { get; init; }
    public required long NumberOfSymbols { get; init; }
    public required long SizeOfOptionalHeader { get; init; }
    public required long Characteristics { get; init; }
    public required long EntryPointRva { get; init; }
    public required long? EntryPointOffset { get; init; }
    public required long ImageBase { get; init; }
    public required long Magic { get; init; }
    public required long Subsystem { get; init; }
    public required long DllCharacteristics { get; init; }
    public required long SizeOfImage { get; init; }
    public required long SizeOfHeaders { get; init; }
    public required long SizeOfCode { get; init; }
    public required long SizeOfInitializedData { get; init; }
    public required long SizeOfUninitializedData { get; init; }
    public required long BaseOfCode { get; init; }
    public required long? BaseOfData { get; init; }
    public required long SectionAlignment { get; init; }
    public required long FileAlignment { get; init; }
    public required long Checksum { get; init; }
    public required long LoaderFlags { get; init; }
    public required long NumberOfRvaAndSizes { get; init; }
    public required long SizeOfStackReserve { get; init; }
    public required long SizeOfStackCommit { get; init; }
    public required long SizeOfHeapReserve { get; init; }
    public required long SizeOfHeapCommit { get; init; }
    public required (long Major, long Minor) LinkerVersion { get; init; }
    public required (long Major, long Minor) OsVersion { get; init; }
    public required (long Major, long Minor) ImageVersion { get; init; }
    public required (long Major, long Minor) SubsystemVersion { get; init; }
    public required long Win32VersionValue { get; init; }
    public required IReadOnlyList<PeModuleSection> Sections { get; init; }
    public required IReadOnlyList<(long VirtualAddress, long Size)> DataDirectories { get; init; }
    public required IReadOnlyList<PeImport> Imports { get; init; }
    public required IReadOnlyList<string> Exports { get; init; }
    public required IReadOnlyDictionary<string, string> VersionInfo { get; init; }
    public required long NumberOfResources { get; init; }
    public required string? ImpHash { get; init; }
    public required string? PdbPath { get; init; }
    public required (long Offset, long Size) Overlay { get; init; }

    public bool Is64Bit => Magic == 0x20B;
    public bool IsDll => (Characteristics & 0x2000) != 0;

    public static PeModuleData? TryBuild(ReadOnlySpan<byte> data)
    {
        if (data.Length < 64 || data[0] != 'M' || data[1] != 'Z' || data.Length > MaxBytes) return null;
        var image = data.ToArray();
        try
        {
            using var reader = new PEReader(ImmutableArray.Create(image));
            var headers = reader.PEHeaders;
            if (headers.PEHeader is not { } pe) return null;
            var coff = headers.CoffHeader;

            var sections = headers.SectionHeaders.Select(s => new PeModuleSection(
                TrimName(s.Name),
                s.VirtualAddress, s.VirtualSize,
                s.PointerToRawData, s.SizeOfRawData,
                (long)(uint)s.SectionCharacteristics,
                s.PointerToRelocations, s.PointerToLineNumbers,
                s.NumberOfRelocations, s.NumberOfLineNumbers)).ToList();

            DirectoryEntry[] dirs =
            [
                pe.ExportTableDirectory, pe.ImportTableDirectory, pe.ResourceTableDirectory, pe.ExceptionTableDirectory,
                pe.CertificateTableDirectory, pe.BaseRelocationTableDirectory, pe.DebugTableDirectory, pe.CopyrightTableDirectory,
                pe.GlobalPointerTableDirectory, pe.ThreadLocalStorageTableDirectory, pe.LoadConfigTableDirectory, pe.BoundImportTableDirectory,
                pe.ImportAddressTableDirectory, pe.DelayImportTableDirectory, pe.CorHeaderTableDirectory, default,
            ];

            var parsed = PeParser.TryParse(image, []);
            var lastRawEnd = sections.Count == 0 ? 0 : sections.Max(s => s.RawDataOffset + s.RawDataSize);
            var overlay = lastRawEnd > 0 && lastRawEnd < image.Length ? (lastRawEnd, image.Length - lastRawEnd) : (0L, 0L);

            return new PeModuleData
            {
                Machine = (ushort)coff.Machine,
                NumberOfSections = coff.NumberOfSections,
                Timestamp = (uint)coff.TimeDateStamp,
                PointerToSymbolTable = (uint)coff.PointerToSymbolTable,
                NumberOfSymbols = (uint)coff.NumberOfSymbols,
                SizeOfOptionalHeader = (ushort)coff.SizeOfOptionalHeader,
                Characteristics = (ushort)coff.Characteristics,
                EntryPointRva = (uint)pe.AddressOfEntryPoint,
                EntryPointOffset = RvaToOffset(sections, (uint)pe.AddressOfEntryPoint, pe.SizeOfHeaders, image.Length),
                ImageBase = (long)pe.ImageBase,
                Magic = (ushort)pe.Magic,
                Subsystem = (ushort)pe.Subsystem,
                DllCharacteristics = (ushort)pe.DllCharacteristics,
                SizeOfImage = (uint)pe.SizeOfImage,
                SizeOfHeaders = (uint)pe.SizeOfHeaders,
                SizeOfCode = (uint)pe.SizeOfCode,
                SizeOfInitializedData = (uint)pe.SizeOfInitializedData,
                SizeOfUninitializedData = (uint)pe.SizeOfUninitializedData,
                BaseOfCode = (uint)pe.BaseOfCode,
                BaseOfData = pe.Magic == PEMagic.PE32 ? (uint)pe.BaseOfData : null,
                SectionAlignment = (uint)pe.SectionAlignment,
                FileAlignment = (uint)pe.FileAlignment,
                Checksum = pe.CheckSum,
                LoaderFlags = 0,
                NumberOfRvaAndSizes = (uint)pe.NumberOfRvaAndSizes,
                SizeOfStackReserve = (long)pe.SizeOfStackReserve,
                SizeOfStackCommit = (long)pe.SizeOfStackCommit,
                SizeOfHeapReserve = (long)pe.SizeOfHeapReserve,
                SizeOfHeapCommit = (long)pe.SizeOfHeapCommit,
                LinkerVersion = (pe.MajorLinkerVersion, pe.MinorLinkerVersion),
                OsVersion = (pe.MajorOperatingSystemVersion, pe.MinorOperatingSystemVersion),
                ImageVersion = (pe.MajorImageVersion, pe.MinorImageVersion),
                SubsystemVersion = (pe.MajorSubsystemVersion, pe.MinorSubsystemVersion),
                Win32VersionValue = 0,
                Sections = sections,
                DataDirectories = dirs.Take(Math.Clamp(pe.NumberOfRvaAndSizes, 0, 16)).Select(d => ((long)(uint)d.RelativeVirtualAddress, (long)(uint)d.Size)).ToList(),
                Imports = parsed?.Imports ?? [],
                Exports = parsed?.Exports ?? [],
                VersionInfo = parsed?.VersionInfo ?? new Dictionary<string, string>(),
                NumberOfResources = parsed?.ResourceCount ?? 0,
                ImpHash = parsed is null ? null : Static.ImpHash.Compute(parsed),
                PdbPath = ReadPdbPath(reader),
                Overlay = overlay,
            };
        }
        catch (BadImageFormatException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static string TrimName(string name)
    {
        var nul = name.IndexOf('\0');
        return nul >= 0 ? name[..nul] : name;
    }

    private static string? ReadPdbPath(PEReader reader)
    {
        try
        {
            foreach (var entry in reader.ReadDebugDirectory())
                if (entry.Type == DebugDirectoryEntryType.CodeView)
                    return reader.ReadCodeViewDebugDirectoryData(entry).Path;
        }
        catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException or ArgumentException)
        {
        }
        return null;
    }

    /// <summary>The file offset of an RVA, or null when no section (or the headers) contains it.</summary>
    public static long? RvaToOffset(IReadOnlyList<PeModuleSection> sections, long rva, long sizeOfHeaders, long fileLength)
    {
        if (rva < 0) return null;
        if (rva < sizeOfHeaders) return rva < fileLength ? rva : null;
        foreach (var s in sections)
        {
            var size = Math.Max(s.VirtualSize, s.RawDataSize);
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
            {
                var offset = s.RawDataOffset + (rva - s.VirtualAddress);
                return offset < fileLength ? offset : null;
            }
        }
        return null;
    }

    public long? RvaToOffset(long rva, long fileLength) => RvaToOffset(Sections, rva, SizeOfHeaders, fileLength);

    /// <summary>Functions imported from a DLL (case-insensitive names, as in YARA); empty when it is not imported.</summary>
    public IEnumerable<string> FunctionsFrom(string dll) =>
        Imports.Where(i => string.Equals(i.Library, dll, StringComparison.OrdinalIgnoreCase)).SelectMany(i => i.Functions);
}

internal sealed record PeModuleSection(
    string Name,
    long VirtualAddress,
    long VirtualSize,
    long RawDataOffset,
    long RawDataSize,
    long Characteristics,
    long PointerToRelocations,
    long PointerToLineNumbers,
    long NumberOfRelocations,
    long NumberOfLineNumbers);

// ---- expressions ------------------------------------------------------------------------

/// <summary>A plain <c>pe.field</c> value.</summary>
internal sealed class PeFieldExpr(YType type, Func<PeModuleData, YVal> read) : YExpr(type)
{
    public override YVal Eval(ref YaraScanState s) => s.GetPe() is { } pe ? read(pe) : YVal.Undefined;
}

/// <summary><c>pe.is_pe</c>: defined for every file, so <c>not pe.is_pe</c> works.</summary>
internal sealed class PeIsPeExpr() : YExpr(YType.Int)
{
    public override YVal Eval(ref YaraScanState s) => YVal.Int(s.GetPe() is null ? 0 : 1);
}

/// <summary><c>pe.sections[i].field</c> and <c>pe.data_directories[i].field</c>.</summary>
internal sealed class PeIndexedExpr(YType type, YExpr index, Func<PeModuleData, long, YVal> read) : YExpr(type, index)
{
    public override YVal Eval(ref YaraScanState s)
    {
        if (s.GetPe() is not { } pe) return YVal.Undefined;
        var i = index.Eval(ref s);
        return i.IsUndefined || i.IsString || i.Value < 0 ? YVal.Undefined : read(pe, i.Value);
    }
}

/// <summary><c>pe.version_info["CompanyName"]</c>.</summary>
internal sealed class PeVersionInfoExpr(YExpr key) : YExpr(YType.String, key)
{
    public override YVal Eval(ref YaraScanState s)
    {
        if (s.GetPe() is not { } pe) return YVal.Undefined;
        var k = key.Eval(ref s);
        return k.IsString && pe.VersionInfo.TryGetValue(k.Text!, out var v) ? YVal.Str(v) : YVal.Undefined;
    }
}

/// <summary>Module functions such as <c>pe.imports("kernel32.dll", "VirtualAlloc")</c>.</summary>
internal sealed class PeCallExpr(YType type, YExpr[] args, Func<PeModuleData, YVal[], long, YVal> call) : YExpr(type, args)
{
    public override YVal Eval(ref YaraScanState s)
    {
        if (s.GetPe() is not { } pe) return YVal.Undefined;
        var values = new YVal[args.Length];
        for (var i = 0; i < args.Length; i++)
        {
            values[i] = args[i].Eval(ref s);
            if (values[i].IsUndefined) return YVal.Undefined;
        }
        return call(pe, values, s.Data.Length);
    }
}
