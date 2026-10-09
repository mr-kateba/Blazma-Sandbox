namespace Blazma.Analysis.Tests.Yara;

public class YaraConditionTests
{
    [Fact]
    public void Booleans_and_logic()
    {
        Assert.True(Y.Cond("true"));
        Assert.False(Y.Cond("false"));
        Assert.True(Y.Cond("not false"));
        Assert.True(Y.Cond("true and (false or true)"));
        Assert.False(Y.Cond("true and false or false"));
        Assert.True(Y.Cond("false or true and true"));
        Assert.True(Y.Cond("not 1 == 2"));
        Assert.True(Y.Cond("1")); // a non-zero integer is true
        Assert.False(Y.Cond("0"));
    }

    [Fact]
    public void Arithmetic_bitwise_and_precedence()
    {
        Assert.True(Y.Cond("1 + 2 * 3 == 7"));
        Assert.True(Y.Cond("(1 + 2) * 3 == 9"));
        Assert.True(Y.Cond("7 \\ 2 == 3 and 7 % 2 == 1"));
        Assert.True(Y.Cond("-5 + 10 == 5 and -(2 - 4) == 2"));
        Assert.True(Y.Cond("0xF0 | 0x0F == 0xFF"));
        Assert.True(Y.Cond("0xF0 & 0x3C == 0x30 and 0xFF ^ 0x0F == 0xF0"));
        Assert.True(Y.Cond("1 << 4 == 16 and 256 >> 4 == 16 and ~0 == -1"));
        Assert.True(Y.Cond("1 | 2 ^ 3 & 4 == 3")); // & binds tighter than ^, which binds tighter than |
        Assert.True(Y.Cond("0o17 == 15 and 0x10 == 16"));
        Assert.True(Y.Cond("2KB == 2048 and 1MB == 1048576"));
        Assert.True(Y.Cond("3 < 4 and 4 <= 4 and 5 > 4 and 4 >= 4 and 1 != 2"));
        Assert.True(Y.Cond("true == true and true != false"));
    }

    [Fact]
    public void Division_by_zero_is_undefined_and_false()
    {
        Assert.False(Y.Cond("1 \\ 0 == 0"));
        Assert.False(Y.Cond("not (1 \\ 0 == 0)")); // not undefined is still undefined
        Assert.True(Y.Cond("1 \\ 0 == 0 or true"));
        Assert.True(Y.Cond("not defined (1 % 0)"));
        Assert.True(Y.Cond("defined (1 % 1)"));
    }

    [Fact]
    public void Filesize()
    {
        Assert.True(Y.Cond("filesize == 5", "12345"));
        Assert.True(Y.Cond("filesize < 1KB", "12345"));
        Assert.False(Y.Cond("filesize > 10", "12345"));
    }

    [Fact]
    public void Integer_reads_little_and_big_endian()
    {
        var data = new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0xFF, 0xFF, 0xFF, 0xFE };
        Assert.True(Y.Matches("", "uint16(0) == 0x5A4D and uint16be(0) == 0x4D5A", data));
        Assert.True(Y.Matches("", "uint8(2) == 0x90 and int8(4) == -1", data));
        Assert.True(Y.Matches("", "uint32(0) == 0x00905A4D and uint32be(0) == 0x4D5A9000", data));
        Assert.True(Y.Matches("", "int32be(4) == -2 and uint32be(4) == 0xFFFFFFFE", data));
        Assert.True(Y.Matches("", "int16(4) == -1 and int16be(6) == -2 and uint8be(0) == 0x4D", data));
        Assert.False(Y.Matches("", "uint32(6) == 0", data)); // past the end: undefined
        Assert.False(Y.Matches("", "uint8(-1) == 0", data));
    }

    [Fact]
    public void Count_offset_length_and_ranges()
    {
        const string strings = "$a = \"ab\"";
        const string data = "ab..ab...ab";
        Assert.True(Y.Matches(strings, "#a == 3", data));
        Assert.True(Y.Matches(strings, "@a[1] == 0 and @a[2] == 4 and @a[3] == 9 and @a == 0", data));
        Assert.True(Y.Matches(strings, "!a[2] == 2 and !a == 2", data));
        Assert.False(Y.Matches(strings, "@a[4] == 0 or @a[0] == 0", data));
        Assert.True(Y.Matches(strings, "$a at 4 and not $a at 5", data));
        Assert.True(Y.Matches(strings, "$a in (5..9) and not $a in (5..8)", data));
        Assert.True(Y.Matches(strings, "#a in (1..10) == 2", data));
        Assert.True(Y.Matches(strings, "$a at 2 + 2", data));
        Assert.False(Y.Matches(strings, "#a > 3", data));
    }

    [Fact]
    public void Of_sets_with_wildcards_counts_and_percentages()
    {
        const string strings = "$a1 = \"one\" $a2 = \"two\" $b = \"three\"";
        Assert.True(Y.Matches(strings, "any of them", "two"));
        Assert.False(Y.Matches(strings, "all of them", "one two"));
        Assert.True(Y.Matches(strings, "all of them", "one two three"));
        Assert.True(Y.Matches(strings, "none of them", "nothing"));
        Assert.False(Y.Matches(strings, "none of them", "three"));
        Assert.True(Y.Matches(strings, "all of ($a*) and #b >= 0", "one two"));
        Assert.False(Y.Matches(strings, "all of ($a*) and #b >= 0", "one three"));
        Assert.True(Y.Matches(strings, "2 of ($a1, $b) and #a2 >= 0", "one three"));
        Assert.False(Y.Matches(strings, "2 of them", "one"));
        Assert.True(Y.Matches(strings, "2 of them", "one three"));
        Assert.True(Y.Matches(strings, "any of ($*)", "three"));
        Assert.True(Y.Matches(strings, "50% of them", "one two")); // 2 of 3 >= 50%
        Assert.False(Y.Matches(strings, "67% of them", "one two")); // needs 3 of 3 (2.01 rounded up)
        Assert.True(Y.Matches(strings, "66% of them", "one two"));
        Assert.True(Y.Matches(strings, "0 of them", "nothing"));
        Assert.False(Y.Matches(strings, "0 of them", "one"));
    }

    [Fact]
    public void Of_with_at_and_in()
    {
        const string strings = "$a = \"MZ\" $b = \"PE\"";
        Assert.True(Y.Matches(strings, "any of them at 0", "MZ..PE"));
        Assert.False(Y.Matches(strings, "all of them at 0", "MZ..PE"));
        Assert.True(Y.Matches(strings, "all of them in (0..10)", "MZ..PE"));
        Assert.False(Y.Matches(strings, "all of them in (0..3)", "MZ..PE"));
    }

    [Fact]
    public void Anonymous_strings()
    {
        const string strings = "$ = \"red\" $ = \"blue\"";
        Assert.True(Y.Matches(strings, "all of them", "red blue"));
        Assert.False(Y.Matches(strings, "all of them", "red"));
        Assert.True(Y.Matches(strings, "any of ($*)", "blue"));
    }

    [Fact]
    public void For_of_loops_bind_the_current_string()
    {
        const string strings = "$a = \"x\" $b = \"y\"";
        Assert.True(Y.Matches(strings, "for all of them : ( # >= 2 )", "xxyy"));
        Assert.False(Y.Matches(strings, "for all of them : ( # >= 2 )", "xxy"));
        Assert.True(Y.Matches(strings, "for any of ($a, $b) : ( $ at 0 )", "yx"));
        Assert.True(Y.Matches(strings, "for any of them : ( @ > 2 )", "...x"));
        Assert.True(Y.Matches(strings, "for 1 of them : ( !  == 1 )", "x"));
        Assert.True(Y.Matches(strings, "for none of them : ( $ in (5..10) )", "xy"));
        Assert.True(Y.Matches(strings, "for all of them : ( @[1] < 2 )", "xy"));
    }

    [Fact]
    public void For_in_loops_over_ranges_and_lists()
    {
        const string strings = "$a = \"ab\"";
        Assert.True(Y.Matches(strings, "for all i in (1..#a) : ( @a[i] % 4 == 0 )", "ab..ab..ab"));
        Assert.False(Y.Matches(strings, "for all i in (1..#a) : ( @a[i] % 4 == 0 )", "ab..ab.ab"));
        Assert.True(Y.Matches(strings, "for any i in (1..#a) : ( uint8(@a[i] + 2) == 0x21 )", "ab..ab!"));
        Assert.True(Y.Matches(strings, "for 2 i in (1..#a) : ( @a[i] > 0 )", "ab.ab.ab"));
        Assert.False(Y.Matches(strings, "for 3 i in (1..#a) : ( @a[i] > 0 )", "ab.ab.ab"));
        Assert.True(Y.Matches(strings, "$a and for any i in (0, 4, 8) : ( $a at i )", "....ab"));
        Assert.True(Y.Matches(strings, "$a and for none i in (1, 2) : ( $a at i )", "ab"));
        Assert.True(Y.Matches(strings, "$a and for all i in (1..2) : ( for any j in (i..i+1) : ( j > 1 ) )", "ab"));
    }

    [Fact]
    public void Empty_loop_ranges_follow_documented_semantics()
    {
        // No iterations: 'any' is false, 'all' is vacuously true, 'none' is true.
        Assert.False(Y.Cond("for any i in (5..1) : ( true )"));
        Assert.True(Y.Cond("for all i in (5..1) : ( false )"));
        Assert.True(Y.Cond("for none i in (5..1) : ( true )"));
        // An undefined bound makes the whole loop undefined.
        Assert.False(Y.Cond("for all i in (0..1 \\ 0) : ( true )"));
    }

    [Fact]
    public void Rule_references_and_sets_of_rules()
    {
        const string rules = """
            rule has_mz { condition: uint16(0) == 0x5A4D }
            rule big { condition: filesize > 3 }
            rule both { condition: has_mz and big }
            rule either { condition: any of (has_*, big) }
            rule two { condition: 2 of (has_mz, big) }
            """;
        var names = Y.Scan(rules, "MZ").Select(m => m.Rule).ToList();
        Assert.Equal(["has_mz", "either"], names);
        names = Y.Scan(rules, "MZxxxx").Select(m => m.Rule).ToList();
        Assert.Equal(["has_mz", "big", "both", "either", "two"], names);
    }

    [Fact]
    public void Private_rules_are_evaluated_but_never_reported()
    {
        const string rules = """
            private rule is_pe { condition: uint16(0) == 0x5A4D }
            rule pe_with_text { strings: $a = "text" condition: is_pe and $a }
            """;
        Assert.Equal(["pe_with_text"], Y.Scan(rules, "MZ text").Select(m => m.Rule));
        Assert.Empty(Y.Scan(rules, "NZ text"));
    }

    [Fact]
    public void Global_rules_gate_every_rule_in_the_same_file()
    {
        const string rules = """
            rule early { condition: true }
            global rule small { condition: filesize < 10 }
            rule late { condition: true }
            """;
        Assert.Equal(["early", "small", "late"], Y.Scan(rules, "tiny").Select(m => m.Rule));
        Assert.Empty(Y.Scan(rules, "far too large for the global rule"));
    }

    [Fact]
    public void Global_rules_do_not_reach_other_files()
    {
        var set = Blazma.Analysis.Yara.YaraRuleSet.FromSources([
            ("global rule never { condition: false } rule a { condition: true }", "one.yar"),
            ("rule b { condition: true }", "two.yar"),
        ]);
        Assert.Equal(["b"], set.Scan("x"u8, "sample").Select(m => m.Rule));
    }

    [Fact]
    public void Private_global_rule_gates_without_being_reported()
    {
        const string rules = """
            private global rule pe_only { condition: uint16(0) == 0x5A4D }
            rule any_file { condition: true }
            """;
        Assert.Equal(["any_file"], Y.Scan(rules, "MZ").Select(m => m.Rule));
        Assert.Empty(Y.Scan(rules, "ELF"));
    }

    [Fact]
    public void Tags_and_meta_reach_the_match()
    {
        const string rule = """
            rule tagged : banker stealer {
                meta:
                    author = "Blazma \"tests\""
                    family = "ExampleBot"
                    score = -10
                    severe = true
                    description = "line\x21"
                condition: true
            }
            """;
        var m = Assert.Single(Y.Scan(rule, "x"));
        Assert.Equal(["banker", "stealer"], m.Tags);
        Assert.Equal("Blazma \"tests\"", m.Meta["author"]);
        Assert.Equal("-10", m.Meta["score"]);
        Assert.Equal("true", m.Meta["severe"]);
        Assert.Equal("line!", m.Meta["description"]);
        Assert.Equal("ExampleBot", m.Family);
        Assert.Equal("test.yar", m.Source);
        Assert.Equal("sample", m.Target);
    }

    [Fact]
    public void Family_falls_back_to_malware_family_and_malware()
    {
        Assert.Equal("Zeus", Assert.Single(Y.Scan("rule r { meta: malware_family = \"Zeus\" condition: true }", "x")).Family);
        Assert.Equal("Emotet", Assert.Single(Y.Scan("rule r { meta: malware = \"Emotet\" condition: true }", "x")).Family);
    }

    [Fact]
    public void Comments_imports_and_underscore_strings()
    {
        const string rules = """
            import "pe" // modules may be imported as long as no rule uses them
            /* a block
               comment */
            rule r {
                strings:
                    $_unused = "never referenced, allowed by the underscore"
                    $a = "x" // trailing comment
                condition:
                    $a /* inline */ and true
            }
            """;
        Assert.Single(Y.Scan(rules, "x"));
    }
}
