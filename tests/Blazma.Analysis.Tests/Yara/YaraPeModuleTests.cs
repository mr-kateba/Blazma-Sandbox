using Blazma.Analysis.Yara;

namespace Blazma.Analysis.Tests.Yara;

/// <summary>
/// The pe module against real PE files: Blazma.Analysis.dll (a PE32 class library built by the .NET
/// SDK, with version information and a PDB path), this test program (an EXE) and System.Private.CoreLib.
/// </summary>
public class YaraPeModuleTests
{
    private static readonly byte[] TestDll = File.ReadAllBytes(typeof(YaraRuleSet).Assembly.Location);

    private static bool Pe(string condition, byte[]? data = null) =>
        Y.Scan($"import \"pe\" rule t {{ condition: {condition} }}", data ?? TestDll).Any(m => m.Rule == "t");

    [Theory]
    [InlineData("pe.is_pe")]
    [InlineData("pe.is_dll()")]
    [InlineData("pe.is_32bit() and not pe.is_64bit()")]
    [InlineData("pe.machine == pe.MACHINE_I386")]
    [InlineData("pe.characteristics & pe.DLL")]
    [InlineData("pe.characteristics & pe.EXECUTABLE_IMAGE")]
    [InlineData("pe.opthdr_magic == pe.IMAGE_NT_OPTIONAL_HDR32_MAGIC")]
    [InlineData("pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI")]
    [InlineData("pe.dll_characteristics & pe.DYNAMIC_BASE and pe.dll_characteristics & pe.NX_COMPAT")]
    [InlineData("pe.number_of_sections >= 2")]
    [InlineData("pe.sections[0].name == \".text\"")]
    [InlineData("pe.sections[0].characteristics & pe.SECTION_MEM_EXECUTE")]
    [InlineData("pe.section_index(\".text\") == 0")]
    [InlineData("pe.section_index(pe.sections[0].raw_data_offset) == 0")]
    [InlineData("for any i in (0 .. pe.number_of_sections - 1) : ( pe.sections[i].name == \".rsrc\" )")]
    [InlineData("pe.imports(\"mscoree.dll\", \"_CorDllMain\")")]
    [InlineData("pe.imports(\"MSCOREE.DLL\", \"_cordllmain\")")]
    [InlineData("pe.imports(\"mscoree.dll\") == 1")]
    [InlineData("pe.number_of_imports == 1")]
    [InlineData("pe.imphash() == \"dae02f32a21e03ce65412f6e56942daa\"")]
    [InlineData("pe.version_info[\"CompanyName\"] == \"Blazma\"")]
    [InlineData("pe.version_info[\"ProductName\"] icontains \"blazma sandbox\"")]
    [InlineData("pe.pdb_path endswith \"Blazma.Analysis.pdb\"")]
    [InlineData("pe.entry_point == pe.rva_to_offset(pe.entry_point_raw)")]
    [InlineData("entrypoint == pe.entry_point")]
    [InlineData("uint16(pe.entry_point) == 0x25FF")]
    [InlineData("pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_IMPORT].size > 0")]
    [InlineData("pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size == 0")]
    [InlineData("pe.overlay.size == 0")]
    [InlineData("pe.linker_version.major > 0")]
    [InlineData("pe.timestamp > 0 or pe.timestamp == 0")]
    public void Reads_a_real_pe(string condition) => Assert.True(Pe(condition), condition);

    [Theory]
    [InlineData("pe.imports(\"kernel32.dll\", \"VirtualAlloc\")")]
    [InlineData("pe.imports(\"mscoree.dll\", \"CreateRemoteThread\")")]
    [InlineData("pe.exports(\"DllRegisterServer\")")]
    [InlineData("pe.sections[99].name == \".text\"")]
    [InlineData("pe.version_info[\"NoSuchKey\"] == \"x\"")]
    [InlineData("pe.section_index(\"UPX0\") >= 0")]
    [InlineData("pe.is_64bit()")]
    public void False_or_undefined_for_what_the_file_does_not_have(string condition) => Assert.False(Pe(condition), condition);

    [Fact]
    public void A_test_program_is_an_exe_importing_the_exe_loader()
    {
        var exe = File.ReadAllBytes(typeof(YaraPeModuleTests).Assembly.Location);
        Assert.True(Pe("not pe.is_dll() and pe.imports(\"mscoree.dll\", \"_CorExeMain\")", exe));
        Assert.True(Pe("pe.imphash() == \"f34d5f2d4577ed6d9ceec516c1f5a744\"", exe));
    }

    [Fact]
    public void Corelib_is_a_64_bit_or_anycpu_image_with_exports_checked_by_name()
    {
        var corelib = File.ReadAllBytes(typeof(object).Assembly.Location);
        Assert.True(Pe("pe.is_pe and pe.number_of_sections > 0", corelib));
        Assert.False(Pe("pe.exports(\"NoSuchExport\")", corelib));
    }

    [Theory]
    [InlineData("pe.is_pe")]
    [InlineData("pe.number_of_sections >= 0")]
    [InlineData("pe.imports(\"kernel32.dll\")")]
    [InlineData("entrypoint >= 0")]
    public void Nothing_matches_on_data_that_is_not_a_pe(string condition) =>
        Assert.False(Pe(condition, Y.Bytes("just some text, not a program")), condition);

    [Fact]
    public void Not_is_pe_matches_other_data()
    {
        Assert.True(Pe("not pe.is_pe", Y.Bytes("MZ but far too short")));
        Assert.True(Pe("not pe.is_pe", Y.Bytes("plain text")));
    }

    [Fact]
    public void A_truncated_or_corrupted_pe_is_not_a_pe_and_does_not_throw()
    {
        var cut = TestDll[..300];
        Assert.False(Pe("pe.is_pe", cut));
        var corrupted = (byte[])TestDll.Clone();
        corrupted[0x3C] = 0xFF; corrupted[0x3D] = 0xFF; corrupted[0x3E] = 0xFF; corrupted[0x3F] = 0x7F;
        Assert.False(Pe("pe.is_pe", corrupted));
    }

    [Fact]
    public void Realistic_rule_combines_strings_and_pe_fields()
    {
        const string rule = """
            import "pe"

            rule Managed_Library : dotnet
            {
                meta:
                    description = "A .NET library (imports only the runtime loader)"
                strings:
                    $bsjb = { 42 53 4A 42 }
                condition:
                    uint16(0) == 0x5A4D and pe.is_dll() and
                    pe.imports("mscoree.dll", "_CorDllMain") and
                    $bsjb and pe.number_of_imports == 1
            }
            """;
        var match = Assert.Single(Y.Scan(rule, TestDll));
        Assert.Equal("Managed_Library", match.Rule);
    }

    [Fact]
    public void String_operators_work_on_text_constants()
    {
        Assert.True(Y.Cond("\"Hello World\" contains \"lo W\""));
        Assert.True(Y.Cond("\"Hello World\" icontains \"LO w\""));
        Assert.True(Y.Cond("\"Hello\" startswith \"He\" and \"Hello\" endswith \"lo\""));
        Assert.True(Y.Cond("\"Hello\" iequals \"hELLO\" and not (\"Hello\" == \"hello\")"));
        Assert.True(Y.Cond("\"a\" != \"b\""));
    }
}
