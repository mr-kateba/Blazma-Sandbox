using Blazma.Analysis.Yara;

namespace Blazma.Analysis.Tests.Yara;

public class YaraCompileErrorTests
{
    [Fact]
    public void Syntax_errors_fail_the_file_with_file_and_line()
    {
        const string source = "rule ok { condition: true }\n\nrule broken {\n  condition: (true\n}";
        var result = YaraCompiler.Compile(source, "rules/bad.yar");
        Assert.Empty(result.Rules);
        var error = Assert.Single(result.Errors);
        Assert.StartsWith("rules/bad.yar:5:", error, StringComparison.Ordinal);
        Assert.Contains("expected ')'", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("rule { condition: true }", 1, "expected a rule name")]
    [InlineData("rule r { condition: }", 1, "unexpected")]
    [InlineData("rule r {\n strings:\n condition: true }", 3, "strings section is empty")]
    [InlineData("rule r { condition: 1.5 > 1 }", 1, "floating-point")]
    [InlineData("rule r { condition: 4 / 2 }", 1, "divides with '\\'")]
    [InlineData("rule r {\n strings: $a = \"abc\n\" condition: $a }", 2, "unterminated text string")]
    [InlineData("rule r { strings: $a = abc condition: $a }", 1, "expected a text string, hex string or regular expression")]
    [InlineData("rule r { condition: true", 1, "expected '}'")]
    [InlineData("rule r { condition: true } /* open", 1, "unterminated comment")]
    [InlineData("rule r { condition: 99999999999999999999 }", 1, "too large")]
    [InlineData("rule r { condition: $a* }", 1, "only valid inside a set")]
    public void Syntax_error_messages(string source, int line, string fragment)
    {
        var error = Y.SingleError(source);
        Assert.StartsWith($"bad.yar:{line}:", error, StringComparison.Ordinal);
        Assert.Contains(fragment, error, StringComparison.Ordinal);
    }

    [Fact]
    public void A_rule_with_a_semantic_error_is_skipped_and_the_rest_load()
    {
        const string source = """
            rule good_one { condition: true }

            rule uses_pe {
                condition:
                    pe.number_of_sections > 2
            }

            rule good_two { condition: filesize > 0 }
            """;
        var result = YaraCompiler.Compile(source, "mixed.yar");
        Assert.Equal(["good_one", "good_two"], result.Rules.Select(r => r.Name));
        var error = Assert.Single(result.Errors);
        Assert.Equal("mixed.yar:5: rule uses_pe: uses the 'pe' module, which is not supported", error);
    }

    [Theory]
    [InlineData("import \"math\" rule r { condition: math.entropy(0, filesize) > 7 }", "'math' module")]
    [InlineData("import \"hash\" rule r { condition: hash.md5(0, filesize) == \"x\" }", "'hash' module")]
    [InlineData("rule r { condition: elf.type == 1 }", "'elf' module")]
    [InlineData("rule r { condition: dotnet.version == 1 }", "'dotnet' module")]
    [InlineData("rule r { condition: cuckoo.network.http_request(/evil/) }", "'cuckoo' module")]
    [InlineData("rule r { condition: magic.mime_type() == 1 }", "'magic' module")]
    [InlineData("rule r { condition: time.now() > 0 }", "'time' module")]
    [InlineData("rule r { condition: console.log(1) }", "'console' module")]
    [InlineData("rule r { condition: pe.sections[0].name == 1 }", "'pe' module")]
    [InlineData("rule r { condition: for any s in pe.sections : ( true ) }", "need modules")]
    [InlineData("rule r { condition: entrypoint == 0 }", "'entrypoint' is not supported")]
    [InlineData("rule r { condition: my_external > 1 }", "undefined identifier 'my_external'")]
    [InlineData("rule r { condition: \"abc\" contains \"b\" }", "not supported")]
    [InlineData("rule r { strings: $a = \"x\" condition: $a and pe.is_dll() matches /x/ }", "'pe' module")]
    [InlineData("rule r { condition: later }  rule later { condition: true }", "undefined identifier 'later'")]
    public void Unsupported_features_name_the_rule_and_line(string source, string fragment)
    {
        var result = YaraCompiler.Compile(source, "u.yar");
        var error = Assert.Single(result.Errors);
        Assert.StartsWith("u.yar:1: rule r: ", error, StringComparison.Ordinal);
        Assert.Contains(fragment, error, StringComparison.Ordinal);
        Assert.DoesNotContain(result.Rules, r => r.Name == "r");
    }

    [Fact]
    public void Include_is_reported_and_the_rest_loads()
    {
        var result = YaraCompiler.Compile("include \"other.yar\"\nrule r { condition: true }", "i.yar");
        Assert.Single(result.Rules);
        Assert.Contains("i.yar:1: 'include' is not supported", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("$a = \"x\" xor nocase", "'xor' and 'nocase' cannot be combined")]
    [InlineData("$a = \"x\" xor fullword", "'xor' with 'fullword' is not supported")]
    [InlineData("$a = \"x\" xor(300)", "xor keys")]
    [InlineData("$a = \"x\" xor(5-2)", "xor keys")]
    [InlineData("$a = \"abc\" base64 nocase", "'base64' cannot be combined")]
    [InlineData("$a = \"abc\" base64 wide", "'ascii'/'wide' is not supported")]
    [InlineData("$a = \"ab\" base64", "at least 3 bytes")]
    [InlineData("$a = \"abc\" base64(\"short\")", "exactly 64 bytes")]
    [InlineData("$a = \"\"", "empty text string")]
    [InlineData("$a = \"\\q\"", "unknown escape")]
    [InlineData("$a = \"\\x4\"", "two hex digits")]
    [InlineData("$a = \"x\" ascii ascii", "duplicate modifier")]
    [InlineData("$a = { 41 42 } nocase", "cannot be used with hex strings")]
    [InlineData("$a = { 41 4}", "incomplete hex byte")]
    [InlineData("$a = { 41 GG }", "invalid hex byte")]
    [InlineData("$a = { [2] 41 }", "cannot start with a jump")]
    [InlineData("$a = { 41 [2] }", "cannot end with a jump")]
    [InlineData("$a = { 41 [5-2] 42 }", "lower bound above upper bound")]
    [InlineData("$a = { 41 [0-70000] 42 }", "larger than the limit")]
    [InlineData("$a = { 41 ( 42 ) 43 }", "at least two options")]
    [InlineData("$a = { 41 ( 42 | ) 43 }", "empty alternative")]
    [InlineData("$a = { 41 ~?? }", "would match nothing")]
    [InlineData("$a = /a\\1/", "backreferences")]
    [InlineData("$a = /a(?=b)/", "'(?' constructs")]
    [InlineData("$a = /(?<!a)b/", "'(?' constructs")]
    [InlineData("$a = /(?i)abc/", "'(?' constructs")]
    [InlineData("$a = /a{1,40000}/", "too large")]
    [InlineData("$a = /[z-a]/", "bad character range")]
    [InlineData("$a = /(ab/", "missing ')'")]
    [InlineData("$a = /ab)/", "unbalanced ')'")]
    [InlineData("$a = /a|*b/", "nothing to repeat")]
    [InlineData("$a = /x/ xor", "cannot be used with regular expressions")]
    [InlineData("$a = /café/", "non-ASCII")]
    public void Bad_string_definitions_skip_the_rule(string strings, string fragment)
    {
        var result = YaraCompiler.Compile($"rule r {{\n strings:\n  {strings}\n condition: $a }}", "s.yar");
        Assert.Empty(result.Rules);
        var error = Assert.Single(result.Errors);
        Assert.StartsWith("s.yar:3: rule r: ", error, StringComparison.Ordinal);
        Assert.Contains(fragment, error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("rule r { strings: $a = \"x\" $b = \"y\" condition: $a }", "string $b is never used")]
    [InlineData("rule r { strings: $a = \"x\" $a = \"y\" condition: $a }", "duplicate string identifier $a")]
    [InlineData("rule r { condition: $nope }", "undefined string $nope")]
    [InlineData("rule r { condition: any of them }", "'them' is used in a rule without strings")]
    [InlineData("rule r { strings: $a = \"x\" condition: any of ($b*) or $a }", "no string matches '$b*'")]
    [InlineData("rule r { strings: $a = \"x\" condition: $ }", "only valid inside 'for ... of'")]
    [InlineData("rule r { strings: $a = \"x\" condition: $a + 1 > 0 }", "needs integer operands")]
    [InlineData("rule r { condition: true == 1 }", "compares a boolean with an integer")]
    [InlineData("rule r { condition: 150% of (x) }", "between 1 and 100")]
    [InlineData("rule r { condition: for any i, j in (1..2) : ( true ) }", "several variables")]
    [InlineData("rule r { strings: $a = \"x\" condition: $a and any of (r2) }", "undefined rule 'r2'")]
    public void Semantic_errors(string source, string fragment)
    {
        var error = Y.SingleError(source);
        Assert.Contains("rule r: ", error, StringComparison.Ordinal);
        Assert.Contains(fragment, error, StringComparison.Ordinal);
    }

    [Fact]
    public void Duplicate_rule_names_and_references_to_skipped_rules()
    {
        const string source = """
            rule a { condition: true }
            rule a { condition: false }
            rule broken { condition: pe.is_dll() }
            rule uses_broken { condition: broken }
            """;
        var result = YaraCompiler.Compile(source, "d.yar");
        Assert.Equal(["a"], result.Rules.Select(r => r.Name));
        Assert.Equal(3, result.Errors.Count);
        Assert.Contains(result.Errors, e => e.StartsWith("d.yar:2: rule a: duplicate rule name", StringComparison.Ordinal));
        Assert.Contains(result.Errors, e => e.StartsWith("d.yar:4: rule uses_broken: references rule broken, which could not be compiled", StringComparison.Ordinal));
    }

    [Fact]
    public void Deep_nesting_is_a_compile_error_not_a_crash()
    {
        var deep = new string('(', 5000) + "true" + new string(')', 5000);
        var result = YaraCompiler.Compile($"rule deep {{ condition: {deep} }}\nrule fine {{ condition: true }}", "n.yar");
        Assert.Equal(["fine"], result.Rules.Select(r => r.Name));
        Assert.Contains("nested more than 64 levels", Assert.Single(result.Errors), StringComparison.Ordinal);

        var nots = string.Concat(Enumerable.Repeat("not ", 5000)) + "true";
        Assert.Contains("nested more than 64", Y.SingleError($"rule r {{ condition: {nots} }}"), StringComparison.Ordinal);

        var minus = string.Concat(Enumerable.Repeat("-", 5000)) + "1 == 1";
        Assert.Contains("nested more than 64", Y.SingleError($"rule r {{ condition: {minus} }}"), StringComparison.Ordinal);
    }

    [Fact]
    public void Long_operator_chains_are_bounded()
    {
        // and/or chains are flat lists, so they are fine at any length.
        var ors = string.Join(" or ", Enumerable.Repeat("false", 20_000)) + " or true";
        Assert.True(Y.Cond(ors));

        // Arithmetic chains build a tree; a very tall one is rejected instead of risking the stack.
        var sum = string.Join(" + ", Enumerable.Repeat("1", 5000)) + " > 0";
        Assert.Contains("too complex", Y.SingleError($"rule r {{ condition: {sum} }}"), StringComparison.Ordinal);
    }

    [Fact]
    public void Deeply_nested_hex_alternatives_and_regex_groups_are_rejected()
    {
        var hex = "41 " + string.Concat(Enumerable.Repeat("( 41 | ", 100)) + "42" + string.Concat(Enumerable.Repeat(" )", 100));
        Assert.Contains("nested more than 64", Y.SingleError($"rule r {{ strings: $a = {{ {hex} }} condition: $a }}"), StringComparison.Ordinal);

        var regex = new string('(', 100) + "a" + new string(')', 100);
        Assert.Contains("nested more than 64", Y.SingleError($"rule r {{ strings: $a = /{regex}/ condition: $a }}"), StringComparison.Ordinal);
    }
}
