using Blazma.Analysis.Yara;

namespace Blazma.Analysis.Tests.Yara;

public class YaraStringTests
{
    // ---- text strings -----------------------------------------------------------------

    [Fact]
    public void Text_string_matches_exact_bytes_only()
    {
        Assert.True(Y.Matches("$a = \"evil\"", "$a", "this is evil code"));
        Assert.False(Y.Matches("$a = \"evil\"", "$a", "this is EVIL code"));
        Assert.False(Y.Matches("$a = \"evil\"", "$a", "ev il"));
    }

    [Fact]
    public void Text_escapes_are_decoded()
    {
        Assert.True(Y.Matches("$a = \"a\\\"b\\\\c\\n\\t\\r\\x00\\xFF\"", "$a", Y.Cat(Y.Bytes("a\"b\\c\n\t\r"), [0x00, 0xFF])));
        Assert.False(Y.Matches("$a = \"\\x41\\x42\"", "$a", "AC"));
        Assert.True(Y.Matches("$a = \"\\x41\\x42\"", "$a", "xxABxx"));
    }

    [Fact]
    public void Non_ascii_characters_are_utf8_bytes()
    {
        Assert.True(Y.Matches("$a = \"café\"", "$a", System.Text.Encoding.UTF8.GetBytes("un café noir")));
        Assert.False(Y.Matches("$a = \"café\"", "$a", Y.Bytes("un café noir"))); // Latin-1 é is one byte
    }

    [Fact]
    public void Nocase_folds_ascii_letters_only()
    {
        Assert.True(Y.Matches("$a = \"PowerShell\" nocase", "$a", "run POWERSHELL now"));
        Assert.True(Y.Matches("$a = \"PowerShell\" nocase", "$a", "powershell"));
        Assert.False(Y.Matches("$a = \"PowerShell\" nocase", "$a", "power shell"));
        Assert.False(Y.Matches("$a = \"a1\" nocase", "$a", "A!")); // digits are not folded
        Assert.False(Y.Matches("$a = \"[\" nocase", "$a", "{")); // '[' and '{' differ by the case bit but are not letters
    }

    [Fact]
    public void Wide_matches_utf16_and_ascii_is_dropped_unless_asked()
    {
        var wide = Y.Wide("call cmd.exe /c");
        Assert.True(Y.Matches("$a = \"cmd.exe\" wide", "$a", wide));
        Assert.False(Y.Matches("$a = \"cmd.exe\" wide", "$a", "cmd.exe"));
        Assert.True(Y.Matches("$a = \"cmd.exe\" wide ascii", "$a", "cmd.exe"));
        Assert.True(Y.Matches("$a = \"cmd.exe\" wide ascii", "$a", wide));
        Assert.False(Y.Matches("$a = \"cmd.exe\"", "$a", wide));
    }

    [Fact]
    public void Wide_nocase_combination()
    {
        Assert.True(Y.Matches("$a = \"cmd.exe\" wide nocase", "$a", Y.Wide("CMD.EXE")));
        Assert.False(Y.Matches("$a = \"cmd.exe\" wide nocase", "$a", Y.Wide("CMD_EXE")));
    }

    [Fact]
    public void Fullword_requires_non_alphanumeric_neighbours()
    {
        const string s = "$a = \"domain\" fullword";
        Assert.True(Y.Matches(s, "$a", "www.domain.com"));
        Assert.True(Y.Matches(s, "$a", "domain"));
        Assert.True(Y.Matches(s, "$a", "(domain)"));
        Assert.False(Y.Matches(s, "$a", "www.mydomain.com"));
        Assert.False(Y.Matches(s, "$a", "domains"));
        Assert.False(Y.Matches(s, "$a", "1domain"));
        // One occurrence inside a word and one standing alone: only the second counts.
        Assert.True(Y.Matches(s, "#a == 1", "mydomain domain"));
    }

    [Fact]
    public void Fullword_on_wide_strings_checks_wide_neighbours()
    {
        const string s = "$a = \"domain\" wide fullword";
        Assert.True(Y.Matches(s, "$a", Y.Wide("www.domain.com")));
        Assert.False(Y.Matches(s, "$a", Y.Wide("mydomain")));
        Assert.False(Y.Matches(s, "$a", Y.Wide("domains")));
    }

    [Fact]
    public void Private_strings_count_in_conditions_but_are_not_reported()
    {
        var matches = Y.Scan("rule t { strings: $a = \"abc\" private $b = \"xyz\" condition: $a and $b }", "abc xyz");
        var m = Assert.Single(matches);
        Assert.All(m.Strings, s => Assert.Equal("$b", s.Identifier));
        Assert.NotEmpty(m.Strings);
    }

    // ---- xor --------------------------------------------------------------------------

    private static byte[] Xor(string s, byte key) => Y.Bytes(s).Select(b => (byte)(b ^ key)).ToArray();

    [Fact]
    public void Xor_finds_every_single_byte_key_including_zero()
    {
        Assert.True(Y.Matches("$a = \"This program\" xor", "$a", Y.Cat(Y.Bytes("junk"), Xor("This program", 0x5A), Y.Bytes("junk"))));
        Assert.True(Y.Matches("$a = \"This program\" xor", "$a", "This program"));
        Assert.True(Y.Matches("$a = \"This program\" xor", "$a", Xor("This program", 0xFF)));
        Assert.False(Y.Matches("$a = \"This program\" xor", "$a", "This progrbm"));
    }

    [Fact]
    public void Xor_key_ranges_are_respected()
    {
        var data = Xor("payload", 0x20);
        Assert.True(Y.Matches("$a = \"payload\" xor(0x20)", "$a", data));
        Assert.False(Y.Matches("$a = \"payload\" xor(0x21)", "$a", data));
        Assert.True(Y.Matches("$a = \"payload\" xor(0x10-0x30)", "$a", data));
        Assert.False(Y.Matches("$a = \"payload\" xor(0x40-0xff)", "$a", data));
        Assert.False(Y.Matches("$a = \"payload\" xor(1-255)", "$a", "payload"));
    }

    [Fact]
    public void Xor_wide_xors_the_zero_bytes_too()
    {
        var wide = Y.Wide("secret").Select(b => (byte)(b ^ 0x41)).ToArray();
        Assert.True(Y.Matches("$a = \"secret\" xor wide", "$a", wide));
        Assert.False(Y.Matches("$a = \"secret\" xor", "$a", wide));
    }

    [Fact]
    public void Xor_reports_the_right_offset_and_count()
    {
        var data = Y.Cat(Y.Bytes("....."), Xor("abcd", 7), Y.Bytes(".."), Xor("abcd", 9));
        Assert.True(Y.Matches("$a = \"abcd\" xor", "#a == 2 and @a[1] == 5 and @a[2] == 11", data));
    }

    [Fact]
    public void Xor_single_byte_string()
    {
        Assert.True(Y.Matches("$a = \"A\" xor(1)", "#a == 1 and @a[1] == 2", Y.Cat(Y.Bytes("AA"), [0x40])));
    }

    // ---- base64 -----------------------------------------------------------------------

    [Fact]
    public void Base64_forms_match_the_yara_documentation()
    {
        var forms = YaraStringFactory.Base64Forms(Y.Bytes("This program cannot"), null).Select(b => System.Text.Encoding.ASCII.GetString(b)).ToList();
        Assert.Equal(["VGhpcyBwcm9ncmFtIGNhbm5vd", "RoaXMgcHJvZ3JhbSBjYW5ub3", "UaGlzIHByb2dyYW0gY2Fubm90"], forms);
    }

    [Fact]
    public void Base64_finds_the_string_at_any_alignment()
    {
        foreach (var prefix in new[] { "", "x", "xy", "xyz" })
        {
            var encoded = Convert.ToBase64String(Y.Bytes(prefix + "This program cannot be run" + "!!"));
            Assert.True(Y.Matches("$a = \"This program cannot\" base64", "$a", encoded), prefix);
        }
        Assert.False(Y.Matches("$a = \"This program cannot\" base64", "$a", Convert.ToBase64String(Y.Bytes("This program can"))));
    }

    [Fact]
    public void Base64wide_and_custom_alphabets()
    {
        var encoded = Convert.ToBase64String(Y.Bytes("hello world, hello"));
        Assert.True(Y.Matches("$a = \"world\" base64wide", "$a", Y.Wide(encoded)));
        Assert.False(Y.Matches("$a = \"world\" base64wide", "$a", encoded));

        // A rotated alphabet: each standard character is replaced by the next one.
        const string std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var rotated = std[1..] + std[0];
        var custom = new string(encoded.TrimEnd('=').Select(c => rotated[std.IndexOf(c, StringComparison.Ordinal)]).ToArray());
        Assert.True(Y.Matches($"$a = \"world\" base64(\"{rotated}\")", "$a", custom));
        Assert.False(Y.Matches($"$a = \"world\" base64(\"{rotated}\")", "$a", encoded));
    }

    // ---- hex strings ------------------------------------------------------------------

    [Fact]
    public void Hex_bytes_and_wildcards()
    {
        var data = new byte[] { 0x00, 0x4D, 0x5A, 0x90, 0x00, 0x03 };
        Assert.True(Y.Matches("$a = { 4D 5A 90 00 }", "$a at 1", data));
        Assert.True(Y.Matches("$a = { 4D ?? 90 }", "$a", data));
        Assert.True(Y.Matches("$a = { 4D 5? 9? }", "$a", data));
        Assert.True(Y.Matches("$a = { 4D ?A ?0 }", "$a", data));
        Assert.False(Y.Matches("$a = { 4D 6? }", "$a", data));
        Assert.False(Y.Matches("$a = { 4D ?B }", "$a", data));
    }

    [Fact]
    public void Hex_negation()
    {
        var data = new byte[] { 0x41, 0x42, 0x43 };
        Assert.True(Y.Matches("$a = { 41 ~43 }", "$a", data));
        Assert.False(Y.Matches("$a = { 41 ~42 }", "$a", data));
        Assert.True(Y.Matches("$a = { 41 ~5? }", "$a", data));
        Assert.False(Y.Matches("$a = { 41 ~4? }", "$a", data));
    }

    [Fact]
    public void Hex_fixed_and_ranged_jumps()
    {
        var data = new byte[] { 0xAA, 1, 2, 3, 0xBB, 0xCC };
        Assert.True(Y.Matches("$a = { AA [3] BB }", "$a", data));
        Assert.False(Y.Matches("$a = { AA [2] BB }", "$a", data));
        Assert.True(Y.Matches("$a = { AA [2-4] BB }", "$a", data));
        Assert.True(Y.Matches("$a = { AA [3-3] BB CC }", "$a", data));
        Assert.False(Y.Matches("$a = { AA [0-2] BB }", "$a", data));
        Assert.True(Y.Matches("$a = { AA [1-] CC }", "$a", data));
        Assert.True(Y.Matches("$a = { AA [-] CC }", "$a", data));
        Assert.False(Y.Matches("$a = { AA [6-] CC }", "$a", data));
        Assert.True(Y.Matches("$a = { AA [20] CC }", "$a", Y.Cat([0xAA], new byte[20], [0xCC])));
        Assert.False(Y.Matches("$a = { AA [20] CC }", "$a", Y.Cat([0xAA], new byte[19], [0xCC])));
    }

    [Fact]
    public void Hex_jumps_are_lazy_so_the_length_is_the_shortest_match()
    {
        var data = new byte[] { 0xAA, 0xBB, 0x00, 0xBB };
        Assert.True(Y.Matches("$a = { AA [0-4] BB }", "!a[1] == 2 and @a[1] == 0", data));
    }

    [Fact]
    public void Unbounded_jump_reaches_far()
    {
        var data = Y.Cat([0x4D, 0x5A], new byte[30_000], [0x50, 0x45, 0x00, 0x00]);
        Assert.True(Y.Matches("$a = { 4D 5A [-] 50 45 00 00 }", "$a and !a == 30006", data));
    }

    [Fact]
    public void Hex_alternatives_including_nested()
    {
        Assert.True(Y.Matches("$a = { 41 ( 42 | 43 ) 44 }", "$a", "ACD"));
        Assert.True(Y.Matches("$a = { 41 ( 42 | 43 ) 44 }", "$a", "ABD"));
        Assert.False(Y.Matches("$a = { 41 ( 42 | 43 ) 44 }", "$a", "AED"));
        Assert.True(Y.Matches("$a = { 41 ( 42 ( 45 | 46 ) | 43 43 ) 44 }", "$a", "ABFD"));
        Assert.True(Y.Matches("$a = { 41 ( 42 ( 45 | 46 ) | 43 43 ) 44 }", "$a", "ACCD"));
        Assert.False(Y.Matches("$a = { 41 ( 42 ( 45 | 46 ) | 43 43 ) 44 }", "$a", "ABCD"));
        Assert.True(Y.Matches("$a = { ( 41 | 42 42 ) 43 }", "$a and @a[1] == 1", "xBBC"));
        Assert.True(Y.Matches("$a = { 41 ( 4? | [2] 5A ) 44 }", "$a", "A..ZD"));
    }

    [Fact]
    public void Hex_strings_allow_comments_and_newlines()
    {
        const string strings = "$a = { 4D 5A // header\n /* block */ 90 }";
        Assert.True(Y.Matches(strings, "$a", new byte[] { 0x4D, 0x5A, 0x90 }));
    }

    [Fact]
    public void Overlapping_matches_are_all_reported()
    {
        Assert.True(Y.Matches("$a = \"aa\"", "#a == 3", "aaaa"));
        Assert.True(Y.Matches("$a = { 61 61 }", "#a == 3 and @a[3] == 2", "aaaa"));
    }

    // ---- regular expressions ----------------------------------------------------------

    [Fact]
    public void Regex_basics()
    {
        Assert.True(Y.Matches("$a = /md5: [0-9a-f]{32}/", "$a", "md5: d41d8cd98f00b204e9800998ecf8427e"));
        Assert.False(Y.Matches("$a = /md5: [0-9a-f]{32}/", "$a", "md5: d41d8cd98f00b204e98"));
        Assert.True(Y.Matches("$a = /(GET|POST) \\/[a-z]+\\.php/", "$a", "POST /gate.php HTTP/1.1"));
        Assert.True(Y.Matches("$a = /a.c/", "$a", "abc"));
        Assert.False(Y.Matches("$a = /a.c/", "$a", "a\nc"));
        Assert.True(Y.Matches("$a = /a.c/s", "$a", "a\nc"));
        Assert.True(Y.Matches("$a = /\\x41\\x42+/", "$a", "ABBB"));
        Assert.True(Y.Matches("$a = /ab{2,}c/", "$a", "abbbc"));
        Assert.False(Y.Matches("$a = /ab{2,}c/", "$a", "abc"));
        Assert.True(Y.Matches("$a = /ab{,1}c/", "$a", "ac"));
    }

    [Fact]
    public void Regex_classes_are_ascii_like_yara()
    {
        Assert.True(Y.Matches("$a = /\\d\\d\\s\\w+/", "$a", "42 abc_9"));
        Assert.False(Y.Matches("$a = /x\\wy/", "$a", Y.Cat(Y.Bytes("x"), [0xE9], Y.Bytes("y")))); // é is not a word byte in YARA
        Assert.True(Y.Matches("$a = /x\\Wy/", "$a", Y.Cat(Y.Bytes("x"), [0xE9], Y.Bytes("y"))));
        Assert.True(Y.Matches("$a = /x[\\x80-\\xff]y/", "$a", Y.Cat(Y.Bytes("x"), [0xE9], Y.Bytes("y"))));
        Assert.True(Y.Matches("$a = /x[^a-z]y/", "$a", Y.Cat(Y.Bytes("x"), [0x00], Y.Bytes("y"))));
    }

    [Fact]
    public void Regex_word_boundaries_ignore_high_bytes()
    {
        Assert.True(Y.Matches("$a = /\\bcmd\\b/", "$a", Y.Cat([0xE9], Y.Bytes("cmd"), [0xE9])));
        Assert.False(Y.Matches("$a = /\\bcmd\\b/", "$a", "xcmd"));
    }

    [Fact]
    public void Regex_anchors_are_start_and_end_of_data()
    {
        Assert.True(Y.Matches("$a = /^MZ/", "$a", "MZ..."));
        Assert.False(Y.Matches("$a = /^MZ/", "$a", ".MZ"));
        Assert.True(Y.Matches("$a = /end$/", "$a", "the end"));
        Assert.False(Y.Matches("$a = /end$/", "$a", "the end\n"));
    }

    [Fact]
    public void Regex_nocase_flag_and_modifier()
    {
        Assert.True(Y.Matches("$a = /invoke-expression/i", "$a", "Invoke-Expression"));
        Assert.True(Y.Matches("$a = /invoke-[a-z]+/ nocase", "$a", "INVOKE-WEBREQUEST"));
        Assert.False(Y.Matches("$a = /invoke-expression/", "$a", "Invoke-Expression"));
    }

    [Fact]
    public void Regex_wide_and_fullword()
    {
        Assert.True(Y.Matches("$a = /c.d\\.exe/ wide", "$a", Y.Wide("run cmd.exe")));
        Assert.False(Y.Matches("$a = /c.d\\.exe/ wide", "$a", "run cmd.exe"));
        Assert.True(Y.Matches("$a = /c.d\\.exe/ wide ascii", "$a", "run cmd.exe"));
        Assert.True(Y.Matches("$a = /evil[0-9]/ fullword", "$a", "an evil1 x"));
        Assert.False(Y.Matches("$a = /evil[0-9]/ fullword", "$a", "an devil1 x"));
    }

    [Fact]
    public void Regex_wide_keeps_word_boundaries_and_anchors()
    {
        Assert.True(Y.Matches("$a = /\\biex\\b/ wide", "$a", Y.Wide("x = iex(1)")));
        Assert.False(Y.Matches("$a = /\\biex\\b/ wide", "$a", Y.Wide("$iexplore")));
        Assert.True(Y.Matches("$a = /\\biex\\b/ wide", "@a[1] == 3 and !a[1] == 6", Y.Cat([0x20], Y.Wide(" iex "))));
        Assert.True(Y.Matches("$a = /^ab/ wide", "$a", Y.Wide("ab")));
        Assert.False(Y.Matches("$a = /^ab/ wide", "$a", Y.Cat([0x20], Y.Wide("ab"))));
        Assert.True(Y.Matches("$a = /ab$/ wide", "$a", Y.Cat([0x20], Y.Wide("ab"))));
        Assert.False(Y.Matches("$a = /ab$/ wide", "$a", Y.Cat(Y.Wide("ab"), [0x20])));
        Assert.False(Y.Matches("$a = /a.c/ wide", "$a", new byte[] { 0x61, 0, 0x41, 0x41, 0x63, 0 })); // '.' is one wide char
    }

    [Fact]
    public void Regex_offsets_and_lengths()
    {
        Assert.True(Y.Matches("$a = /ab+/", "#a == 2 and @a[1] == 2 and !a[1] == 3 and @a[2] == 7", "..abb..ab"));
    }

    [Fact]
    public void Regex_matches_are_limited_to_4096_bytes_like_yara()
    {
        var run = new string('a', 10_000);
        Assert.True(Y.Matches("$a = /a+/", "!a[1] == 4096 and @a[2] == 1", run));
        Assert.False(Y.Matches("$a = /a{5000}/", "$a", run)); // longer than any match YARA can return
        Assert.True(Y.Matches("$a = /a{4000}/", "$a", run));
        Assert.True(Y.Matches("$a = /x.{4094}y/s", "$a", "x" + new string('.', 4094) + "y"));
        Assert.False(Y.Matches("$a = /x.{4095}y/s", "$a", "x" + new string('.', 4095) + "y"));
    }

    [Fact]
    public void Regex_word_boundaries_work_deep_into_large_data()
    {
        // Regression: .NET's non-backtracking engine missed this with a match timeout set.
        var data = new byte[3 * 1024 * 1024];
        new Random(7).NextBytes(data);
        Y.Bytes(" IEX ").CopyTo(data, 2 * 1024 * 1024);
        Assert.True(Y.Matches("$a = /\\bIEX\\b/", $"$a at {2 * 1024 * 1024 + 1}", data));
    }

    [Fact]
    public void Regex_prefilter_does_not_hide_matches()
    {
        // The required literal is "bc": present only via the repetition, never as "abc".
        Assert.True(Y.Matches("$a = /ab+c/", "$a", "xabbbcx"));
        Assert.False(Y.Matches("$a = /ab+c/", "$a", "xabbbx"));
    }

    [Fact]
    public void Matched_strings_are_reported_with_offsets_and_previews()
    {
        var m = Assert.Single(Y.Scan("rule t { strings: $a = \"cmd.exe\" wide $b = { 4D 5A 90 00 } condition: any of them }",
            Y.Cat(new byte[] { 0x4D, 0x5A, 0x90, 0 }, Y.Wide("cmd.exe"))));
        Assert.Contains(m.Strings, s => s.Identifier == "$a" && s.Offset == 4 && s.Preview == "cmd.exe");
        Assert.Contains(m.Strings, s => s.Identifier == "$b" && s.Offset == 0 && s.Preview == "4D 5A 90 00");
    }

    [Fact]
    public void Reports_are_capped()
    {
        var data = Y.Bytes(string.Concat(Enumerable.Repeat("abc ", 50)));
        var strings = string.Join(' ', Enumerable.Range(0, 15).Select(i => $"$s{i} = \"abc\""));
        var m = Assert.Single(Y.Scan($"rule t {{ strings: {strings} condition: all of them }}", data));
        Assert.Equal(YaraLimits.MaxReportedStrings, m.Strings.Select(s => s.Identifier).Distinct().Count());
        Assert.All(m.Strings.GroupBy(s => s.Identifier), g => Assert.Equal(YaraLimits.MaxReportedHitsPerString, g.Count()));
    }
}
