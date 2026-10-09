namespace Blazma.Analysis.Yara;

/// <summary>The YARA <c>pe</c> module: the fields and functions that published rules use most.</summary>
internal sealed partial class YaraParser
{
    private readonly HashSet<string> _imports = new(StringComparer.Ordinal);

    private static readonly Dictionary<string, long> PeConstants = new(StringComparer.Ordinal)
    {
        // Machine
        ["MACHINE_UNKNOWN"] = 0x0, ["MACHINE_I386"] = 0x14c, ["MACHINE_AMD64"] = 0x8664, ["MACHINE_ARM"] = 0x1c0,
        ["MACHINE_ARMNT"] = 0x1c4, ["MACHINE_ARM64"] = 0xaa64, ["MACHINE_IA64"] = 0x200, ["MACHINE_THUMB"] = 0x1c2,
        // Subsystem
        ["SUBSYSTEM_UNKNOWN"] = 0, ["SUBSYSTEM_NATIVE"] = 1, ["SUBSYSTEM_WINDOWS_GUI"] = 2, ["SUBSYSTEM_WINDOWS_CUI"] = 3,
        ["SUBSYSTEM_OS2_CUI"] = 5, ["SUBSYSTEM_POSIX_CUI"] = 7, ["SUBSYSTEM_NATIVE_WINDOWS"] = 8, ["SUBSYSTEM_WINDOWS_CE_GUI"] = 9,
        ["SUBSYSTEM_EFI_APPLICATION"] = 10, ["SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"] = 11, ["SUBSYSTEM_EFI_RUNTIME_DRIVER"] = 12,
        ["SUBSYSTEM_EFI_ROM_IMAGE"] = 13, ["SUBSYSTEM_XBOX"] = 14, ["SUBSYSTEM_WINDOWS_BOOT_APPLICATION"] = 16,
        // File characteristics
        ["RELOCS_STRIPPED"] = 0x1, ["EXECUTABLE_IMAGE"] = 0x2, ["LINE_NUMS_STRIPPED"] = 0x4, ["LOCAL_SYMS_STRIPPED"] = 0x8,
        ["AGGRESIVE_WS_TRIM"] = 0x10, ["LARGE_ADDRESS_AWARE"] = 0x20, ["BYTES_REVERSED_LO"] = 0x80, ["MACHINE_32BIT"] = 0x100,
        ["DEBUG_STRIPPED"] = 0x200, ["REMOVABLE_RUN_FROM_SWAP"] = 0x400, ["NET_RUN_FROM_SWAP"] = 0x800, ["SYSTEM"] = 0x1000,
        ["DLL"] = 0x2000, ["UP_SYSTEM_ONLY"] = 0x4000, ["BYTES_REVERSED_HI"] = 0x8000,
        // DLL characteristics
        ["HIGH_ENTROPY_VA"] = 0x20, ["DYNAMIC_BASE"] = 0x40, ["FORCE_INTEGRITY"] = 0x80, ["NX_COMPAT"] = 0x100,
        ["NO_ISOLATION"] = 0x200, ["NO_SEH"] = 0x400, ["NO_BIND"] = 0x800, ["APPCONTAINER"] = 0x1000, ["WDM_DRIVER"] = 0x2000,
        ["GUARD_CF"] = 0x4000, ["TERMINAL_SERVER_AWARE"] = 0x8000,
        // Optional header magic
        ["IMAGE_NT_OPTIONAL_HDR32_MAGIC"] = 0x10b, ["IMAGE_NT_OPTIONAL_HDR64_MAGIC"] = 0x20b, ["IMAGE_ROM_OPTIONAL_HDR_MAGIC"] = 0x107,
        // Section characteristics
        ["SECTION_NO_PAD"] = 0x8, ["SECTION_CNT_CODE"] = 0x20, ["SECTION_CNT_INITIALIZED_DATA"] = 0x40,
        ["SECTION_CNT_UNINITIALIZED_DATA"] = 0x80, ["SECTION_LNK_OTHER"] = 0x100, ["SECTION_LNK_INFO"] = 0x200,
        ["SECTION_LNK_REMOVE"] = 0x800, ["SECTION_LNK_COMDAT"] = 0x1000, ["SECTION_GPREL"] = 0x8000,
        ["SECTION_LNK_NRELOC_OVFL"] = 0x1000000, ["SECTION_MEM_DISCARDABLE"] = 0x2000000, ["SECTION_MEM_NOT_CACHED"] = 0x4000000,
        ["SECTION_MEM_NOT_PAGED"] = 0x8000000, ["SECTION_MEM_SHARED"] = 0x10000000, ["SECTION_MEM_EXECUTE"] = 0x20000000,
        ["SECTION_MEM_READ"] = 0x40000000, ["SECTION_MEM_WRITE"] = 0x80000000,
        // Data directory indexes
        ["IMAGE_DIRECTORY_ENTRY_EXPORT"] = 0, ["IMAGE_DIRECTORY_ENTRY_IMPORT"] = 1, ["IMAGE_DIRECTORY_ENTRY_RESOURCE"] = 2,
        ["IMAGE_DIRECTORY_ENTRY_EXCEPTION"] = 3, ["IMAGE_DIRECTORY_ENTRY_SECURITY"] = 4, ["IMAGE_DIRECTORY_ENTRY_BASERELOC"] = 5,
        ["IMAGE_DIRECTORY_ENTRY_DEBUG"] = 6, ["IMAGE_DIRECTORY_ENTRY_ARCHITECTURE"] = 7, ["IMAGE_DIRECTORY_ENTRY_COPYRIGHT"] = 7,
        ["IMAGE_DIRECTORY_ENTRY_GLOBALPTR"] = 8, ["IMAGE_DIRECTORY_ENTRY_TLS"] = 9, ["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"] = 10,
        ["IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"] = 11, ["IMAGE_DIRECTORY_ENTRY_IAT"] = 12, ["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"] = 13,
        ["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"] = 14,
    };

    private static readonly Dictionary<string, Func<PeModuleData, long?>> PeIntFields = new(StringComparer.Ordinal)
    {
        ["machine"] = p => p.Machine,
        ["number_of_sections"] = p => p.NumberOfSections,
        ["timestamp"] = p => p.Timestamp,
        ["pointer_to_symbol_table"] = p => p.PointerToSymbolTable,
        ["number_of_symbols"] = p => p.NumberOfSymbols,
        ["size_of_optional_header"] = p => p.SizeOfOptionalHeader,
        ["characteristics"] = p => p.Characteristics,
        ["entry_point"] = p => p.EntryPointOffset,
        ["entry_point_raw"] = p => p.EntryPointRva,
        ["image_base"] = p => p.ImageBase,
        ["opthdr_magic"] = p => p.Magic,
        ["subsystem"] = p => p.Subsystem,
        ["dll_characteristics"] = p => p.DllCharacteristics,
        ["size_of_image"] = p => p.SizeOfImage,
        ["size_of_headers"] = p => p.SizeOfHeaders,
        ["size_of_code"] = p => p.SizeOfCode,
        ["size_of_initialized_data"] = p => p.SizeOfInitializedData,
        ["size_of_uninitialized_data"] = p => p.SizeOfUninitializedData,
        ["base_of_code"] = p => p.BaseOfCode,
        ["base_of_data"] = p => p.BaseOfData,
        ["section_alignment"] = p => p.SectionAlignment,
        ["file_alignment"] = p => p.FileAlignment,
        ["checksum"] = p => p.Checksum,
        ["loader_flags"] = p => p.LoaderFlags,
        ["number_of_rva_and_sizes"] = p => p.NumberOfRvaAndSizes,
        ["size_of_stack_reserve"] = p => p.SizeOfStackReserve,
        ["size_of_stack_commit"] = p => p.SizeOfStackCommit,
        ["size_of_heap_reserve"] = p => p.SizeOfHeapReserve,
        ["size_of_heap_commit"] = p => p.SizeOfHeapCommit,
        ["win32_version_value"] = p => p.Win32VersionValue,
        ["number_of_imports"] = p => p.Imports.Count,
        ["number_of_imported_functions"] = p => p.Imports.Sum(i => i.Functions.Count),
        ["number_of_exports"] = p => p.Exports.Count,
        ["number_of_resources"] = p => p.NumberOfResources,
    };

    private static readonly Dictionary<string, Func<PeModuleSection, YVal>> PeSectionFields = new(StringComparer.Ordinal)
    {
        ["name"] = s => YVal.Str(s.Name),
        ["full_name"] = s => YVal.Str(s.Name),
        ["virtual_address"] = s => YVal.Int(s.VirtualAddress),
        ["virtual_size"] = s => YVal.Int(s.VirtualSize),
        ["raw_data_offset"] = s => YVal.Int(s.RawDataOffset),
        ["raw_data_size"] = s => YVal.Int(s.RawDataSize),
        ["characteristics"] = s => YVal.Int(s.Characteristics),
        ["pointer_to_relocations"] = s => YVal.Int(s.PointerToRelocations),
        ["pointer_to_line_numbers"] = s => YVal.Int(s.PointerToLineNumbers),
        ["number_of_relocations"] = s => YVal.Int(s.NumberOfRelocations),
        ["number_of_line_numbers"] = s => YVal.Int(s.NumberOfLineNumbers),
    };

    private void RecordImport(Token module) => _imports.Add(YaraEscapes.ToText(module.Text, out _));

    /// <summary>The deprecated <c>entrypoint</c> keyword: the entry point's file offset, as <c>pe.entry_point</c>.</summary>
    private static YExpr EntryPointExpr() =>
        new PeFieldExpr(YType.Int, p => p.EntryPointOffset is { } o ? YVal.Int(o) : YVal.Undefined);

    /// <summary>Parses what follows <c>pe</c>; the module name has been consumed and a '.' is next.</summary>
    private YExpr ParsePe(Token module)
    {
        if (!_imports.Contains("pe"))
        {
            SkipModuleAccess();
            _rb.Fail(module.Line, "uses the 'pe' module without 'import \"pe\"' at the top of the file");
            return new UnknownExpr();
        }
        ExpectPunct(".");
        var field = Expect(TokenKind.Identifier, "a pe field name");
        var name = field.Text;

        if (PeConstants.TryGetValue(name, out var constant)) return new ConstExpr(YVal.Int(constant), YType.Int);
        if (name == "is_pe") return new PeIsPeExpr();
        if (PeIntFields.TryGetValue(name, out var read))
            return new PeFieldExpr(YType.Int, p => read(p) is { } v ? YVal.Int(v) : YVal.Undefined);

        switch (name)
        {
            case "pdb_path":
                return new PeFieldExpr(YType.String, p => YVal.Str(p.PdbPath));
            case "linker_version" or "os_version" or "image_version" or "subsystem_version":
                {
                    ExpectPunct(".");
                    var part = Expect(TokenKind.Identifier, "major or minor");
                    if (part.Text is not ("major" or "minor")) { _rb.Fail(part.Line, $"pe.{name} has no field '{part.Text}'"); return new UnknownExpr(); }
                    var major = part.Text == "major";
                    return new PeFieldExpr(YType.Int, p =>
                    {
                        var v = name switch { "linker_version" => p.LinkerVersion, "os_version" => p.OsVersion, "image_version" => p.ImageVersion, _ => p.SubsystemVersion };
                        return YVal.Int(major ? v.Major : v.Minor);
                    });
                }
            case "overlay":
                {
                    ExpectPunct(".");
                    var part = Expect(TokenKind.Identifier, "offset or size");
                    if (part.Text is not ("offset" or "size")) { _rb.Fail(part.Line, $"pe.overlay has no field '{part.Text}'"); return new UnknownExpr(); }
                    var offset = part.Text == "offset";
                    return new PeFieldExpr(YType.Int, p => YVal.Int(offset ? p.Overlay.Offset : p.Overlay.Size));
                }
            case "sections":
                {
                    if (!_lex.Peek().IsPunct("[")) break;
                    var index = ParseIndex(field);
                    ExpectPunct(".");
                    var part = Expect(TokenKind.Identifier, "a section field");
                    if (!PeSectionFields.TryGetValue(part.Text, out var sectionField)) { _rb.Fail(part.Line, $"pe.sections[] has no field '{part.Text}'"); return new UnknownExpr(); }
                    var type = part.Text is "name" or "full_name" ? YType.String : YType.Int;
                    return Checked(new PeIndexedExpr(type, index, (p, i) => i < p.Sections.Count ? sectionField(p.Sections[(int)i]) : YVal.Undefined), field.Line);
                }
            case "data_directories":
                {
                    if (!_lex.Peek().IsPunct("[")) break;
                    var index = ParseIndex(field);
                    ExpectPunct(".");
                    var part = Expect(TokenKind.Identifier, "virtual_address or size");
                    if (part.Text is not ("virtual_address" or "size")) { _rb.Fail(part.Line, $"pe.data_directories[] has no field '{part.Text}'"); return new UnknownExpr(); }
                    var address = part.Text == "virtual_address";
                    return Checked(new PeIndexedExpr(YType.Int, index, (p, i) => i < p.DataDirectories.Count
                        ? YVal.Int(address ? p.DataDirectories[(int)i].VirtualAddress : p.DataDirectories[(int)i].Size)
                        : YVal.Undefined), field.Line);
                }
            case "version_info":
                {
                    if (!_lex.Peek().IsPunct("[")) break;
                    _lex.Next();
                    var key = ParseExpression();
                    ExpectPunct("]");
                    if (key.Type != YType.String) { _rb.Fail(field.Line, "pe.version_info needs a text key such as \"CompanyName\""); return new UnknownExpr(); }
                    return Checked(new PeVersionInfoExpr(key), field.Line);
                }
        }

        if (_lex.Peek().IsPunct("(")) return ParsePeCall(field);

        SkipModuleAccess();
        _rb.Fail(field.Line, $"pe.{name} is not supported yet");
        return new UnknownExpr();
    }

    private YExpr ParseIndex(Token field)
    {
        ExpectPunct("[");
        var index = ParseExpression();
        ExpectPunct("]");
        RequireInt(index, field);
        return index;
    }

    private YExpr ParsePeCall(Token function)
    {
        _lex.Next(); // (
        var args = new List<YExpr>();
        // Check for a regex before peeking: a lookahead token would hide the raw '/'.
        if (_lex.RawNextIs('/') || !_lex.Peek().IsPunct(")"))
        {
            while (true)
            {
                if (_lex.RawNextIs('/'))
                {
                    _lex.ReadRegexOperand();
                    _rb.Fail(function.Line, $"pe.{function.Text}() with a regular expression is not supported yet");
                    args.Add(new UnknownExpr());
                }
                else args.Add(ParseExpression());
                if (_lex.Peek().IsPunct(",")) { _lex.Next(); continue; }
                break;
            }
        }
        ExpectPunct(")");

        bool Shape(params YType[] types) =>
            args.Count == types.Length && args.Zip(types).All(x => x.First.Type == x.Second || x.First.Type == YType.Unknown);

        YExpr Call(YType type, Func<PeModuleData, YVal[], long, YVal> fn) => Checked(new PeCallExpr(type, [.. args], fn), function.Line);

        switch (function.Text)
        {
            case "imports" when Shape(YType.String):
                return Call(YType.Int, (p, a, _) => YVal.Int(p.FunctionsFrom(a[0].Text!).Count()));
            case "imports" when Shape(YType.String, YType.String):
                return Call(YType.Bool, (p, a, _) => YVal.Bool(p.FunctionsFrom(a[0].Text!).Any(f => string.Equals(f, a[1].Text, StringComparison.OrdinalIgnoreCase))));
            case "imports" when Shape(YType.String, YType.Int):
                return Call(YType.Bool, (p, a, _) => YVal.Bool(p.FunctionsFrom(a[0].Text!).Contains("#" + a[1].Value.ToString(System.Globalization.CultureInfo.InvariantCulture))));
            case "exports" when Shape(YType.String):
                return Call(YType.Bool, (p, a, _) => YVal.Bool(p.Exports.Contains(a[0].Text!, StringComparer.Ordinal)));
            case "imphash" when Shape():
                return Call(YType.String, (p, _, _) => YVal.Str(p.ImpHash));
            case "is_dll" when Shape():
                return Call(YType.Int, (p, _, _) => YVal.Int(p.IsDll ? 1 : 0));
            case "is_32bit" when Shape():
                return Call(YType.Int, (p, _, _) => YVal.Int(p.Is64Bit ? 0 : 1));
            case "is_64bit" when Shape():
                return Call(YType.Int, (p, _, _) => YVal.Int(p.Is64Bit ? 1 : 0));
            case "section_index" when Shape(YType.String):
                return Call(YType.Int, (p, a, _) =>
                {
                    for (var i = 0; i < p.Sections.Count; i++)
                        if (string.Equals(p.Sections[i].Name, a[0].Text, StringComparison.Ordinal)) return YVal.Int(i);
                    return YVal.Undefined;
                });
            case "section_index" when Shape(YType.Int):
                return Call(YType.Int, (p, a, _) =>
                {
                    for (var i = 0; i < p.Sections.Count; i++)
                    {
                        var s = p.Sections[i];
                        if (a[0].Value >= s.RawDataOffset && a[0].Value < s.RawDataOffset + s.RawDataSize) return YVal.Int(i);
                    }
                    return YVal.Undefined;
                });
            case "rva_to_offset" when Shape(YType.Int):
                return Call(YType.Int, (p, a, length) => p.RvaToOffset(a[0].Value, length) is { } o ? YVal.Int(o) : YVal.Undefined);
        }
        _rb.Fail(function.Line, $"pe.{function.Text}() with these arguments is not supported");
        return new UnknownExpr();
    }
}
