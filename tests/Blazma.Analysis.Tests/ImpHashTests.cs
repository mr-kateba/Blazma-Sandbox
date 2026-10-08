using Blazma.Analysis.Static;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Tests;

/// <summary>Expected values were produced by Python pefile 2024.8.26 <c>get_imphash()</c> on the same bytes.</summary>
public class ImpHashTests
{
    private static readonly (string, string[])[] Mixed =
    [
        ("KERNEL32.dll", ["CreateFileW", "ReadFile"]),
        ("WS2_32.dll", ["#115", "#23", "#9999"]),
        ("oleaut32.DLL", ["#2", "#6", "#4242"]),
        ("WSOCK32.dll", ["#1", "#1111"]),
        ("MyCtl.ocx", ["Foo"]),
        ("Driver.SYS", ["#5", "Bar"]),
        ("helper.drv", ["#7", "?Mangled@@YAXXZ"]),
        ("ws2_32", ["#115"]),
        ("USER32.dll", ["MessageBoxA", "Bad-Name", "#0"]),
    ];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Matches_pefile_on_ordinals_extensions_and_invalid_names(bool is64)
    {
        var pe = PeParser.TryParse(MiniPe.Build(is64, Mixed), []);
        Assert.NotNull(pe);
        Assert.Equal("5173e9a8085a3586ea69f2a424316934", ImpHash.Compute(pe!));
    }

    [Fact]
    public void Builds_the_same_string_as_pefile()
    {
        // pefile: lower-cased stem, ordinals resolved for ws2_32/wsock32/oleaut32 only, else "ordN".
        var expected = string.Join(',',
            "kernel32.createfilew", "kernel32.readfile",
            "ws2_32.wsastartup", "ws2_32.socket", "ws2_32.ord9999",
            "oleaut32.sysallocstring", "oleaut32.sysfreestring", "oleaut32.ord4242",
            "wsock32.accept", "wsock32.enumprotocolsa",
            "myctl.foo", "driver.ord5", "driver.bar",
            "helper.drv.ord7", "helper.drv.?mangled@@yaxxz",
            "ws2_32.ord115", // no ".dll": pefile's lookup key does not match, so no name
            "user32.messageboxa"); // "Bad-Name" is invalid in pefile, ordinal 0 is dropped
#pragma warning disable CA5351 // MD5 is what the imphash format is defined with
        var md5 = Convert.ToHexStringLower(System.Security.Cryptography.MD5.HashData(System.Text.Encoding.ASCII.GetBytes(expected)));
#pragma warning restore CA5351
        Assert.Equal("5173e9a8085a3586ea69f2a424316934", md5);
    }

    [Fact]
    public void No_imports_gives_no_hash()
    {
        var pe = PeParser.TryParse(MiniPe.Build(false), []);
        Assert.NotNull(pe);
        Assert.Null(ImpHash.Compute(pe!));
        Assert.Null(ImpHash.Compute([new PeImport("KERNEL32.dll", [])]));
    }

    [Fact]
    public void Managed_assembly_has_the_well_known_CorDllMain_hash()
    {
        var pe = PeParser.TryParse(File.ReadAllBytes(typeof(ImpHash).Assembly.Location), []);
        Assert.Equal("dae02f32a21e03ce65412f6e56942daa", ImpHash.Compute(pe!));
    }

    /// <summary>
    /// Real Microsoft-signed native PEs from packages this test project itself restores (the test
    /// SDK), so they exist wherever the tests can run; nothing is copied into the repository.
    /// </summary>
    [Theory]
    [InlineData("microsoft.codecoverage/18.10.1/build/netstandard2.0/CodeCoverage/CodeCoverage.exe", "b6c546047eeb7b3a5758a87f454e5b5e")]
    [InlineData("microsoft.codecoverage/18.10.1/build/netstandard2.0/CodeCoverage/amd64/CodeCoverage.exe", "5256c3df00e50662de973dce39f50ba3")]
    [InlineData("microsoft.codecoverage/18.10.1/build/netstandard2.0/CodeCoverage/amd64/covrun64.dll", "ecdda6daef71935b96049a302773f652")]
    [InlineData("microsoft.codecoverage/18.10.1/build/netstandard2.0/x64/MicrosoftInstrumentationEngine_x64.dll", "352557d8d8e7fc320fab2d2318a0c907")]
    [InlineData("microsoft.testplatform.testhost/18.10.1/build/net8.0/x64/testhost.exe", "bb3ac2c21e02c68abcad237dc3fa6d00")]
    [InlineData("microsoft.testplatform.testhost/18.10.1/build/net8.0/x86/testhost.x86.exe", "6cd1fece03c328d89ab8176a1dbe9927")]
    public void Matches_pefile_on_real_native_files(string relativePath, string expected)
    {
        var root = Environment.GetEnvironmentVariable("NUGET_PACKAGES") is { Length: > 0 } custom
            ? custom
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
        var path = Path.Combine(root, relativePath);
        if (!File.Exists(path)) return; // a different package cache layout; the synthetic vectors still run
        var pe = PeParser.TryParse(File.ReadAllBytes(path), []);
        Assert.Equal(expected, ImpHash.Compute(pe!));
    }
}
