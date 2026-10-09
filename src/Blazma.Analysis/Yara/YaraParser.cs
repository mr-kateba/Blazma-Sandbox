using System.Globalization;

namespace Blazma.Analysis.Yara;

/// <summary>
/// Recursive-descent parser for YARA rule files. Syntax errors reject the whole file; a rule
/// that is well-formed but uses something Blazma does not support (modules, external
/// variables, string operators) is parsed to its end, skipped, and reported with its name
/// and line, so the rest of the file still loads.
/// </summary>
internal sealed class YaraParser(string source, string origin)
{
    private static readonly HashSet<string> KnownModules = new(StringComparer.Ordinal)
    {
        "pe", "elf", "math", "hash", "dotnet", "cuckoo", "magic", "time", "console", "string", "macho", "dex", "lnk",
    };

    private static readonly HashSet<string> Modifiers = new(StringComparer.Ordinal)
    {
        "ascii", "wide", "nocase", "fullword", "private", "xor", "base64", "base64wide",
    };

    private static readonly HashSet<string> StringOperators = new(StringComparer.Ordinal)
    {
        "contains", "icontains", "startswith", "istartswith", "endswith", "iendswith", "iequals", "matches",
    };

    private readonly YaraLexer _lex = new(source);
    private readonly List<YaraRule> _rules = [];
    private readonly Dictionary<string, int> _ruleIndex = new(StringComparer.Ordinal);
    private readonly HashSet<string> _failedRules = new(StringComparer.Ordinal);
    private readonly List<string> _errors = [];
    private RuleBuilder _rb = null!;

    public YaraCompilation Parse()
    {
        try
        {
            while (true)
            {
                var t = _lex.Peek();
                if (t.Kind == TokenKind.End) break;
                if (t.IsWord("import"))
                {
                    _lex.Next();
                    Expect(TokenKind.Text, "a module name in quotes");
                    continue;
                }
                if (t.IsWord("include"))
                {
                    _lex.Next();
                    Expect(TokenKind.Text, "a file name in quotes");
                    _errors.Add($"{origin}:{t.Line}: 'include' is not supported; put every rule file in the rules folder instead");
                    continue;
                }
                ParseRule();
            }
        }
        catch (YaraSyntaxException ex)
        {
            return new YaraCompilation(origin, [], [.. _errors, $"{origin}:{ex.Line}: {ex.Message}"]);
        }
        return new YaraCompilation(origin, _rules, _errors);
    }

    // ---- rules ------------------------------------------------------------------------

    /// <summary>Per-rule parsing state: the first error found, strings, loop variables.</summary>
    private sealed class RuleBuilder(string name, int line)
    {
        public string Name { get; } = name;
        public int Line { get; } = line;
        public string? Error { get; private set; }
        public int ErrorLine { get; private set; }
        public List<YaraString> Strings { get; } = [];
        public List<int> StringLines { get; } = [];
        public Dictionary<string, int> StringIndex { get; } = new(StringComparer.Ordinal);
        public HashSet<int> Referenced { get; } = [];
        public List<(string Name, int Slot)> Vars { get; } = [];
        public int MaxSlots { get; set; }
        public int ForOfDepth { get; set; }
        public int Depth { get; set; }

        public void Fail(int line, string message)
        {
            if (Error is not null) return;
            Error = message;
            ErrorLine = line;
        }
    }

    /// <summary>Stops parsing a condition that is too deep; the rest of the rule is skipped.</summary>
    private sealed class RuleAbortException(int line, string message) : Exception(message)
    {
        public int Line { get; } = line;
    }

    private void ParseRule()
    {
        bool isPrivate = false, isGlobal = false;
        while (_lex.Peek().IsWord("private") || _lex.Peek().IsWord("global"))
        {
            var m = _lex.Next();
            if (m.Text == "private") isPrivate = true;
            else isGlobal = true;
        }
        ExpectWord("rule");
        var nameTok = _lex.Next();
        if (nameTok.Kind != TokenKind.Identifier || YaraLexer.Keywords.Contains(nameTok.Text))
            throw new YaraSyntaxException(nameTok.Line, $"expected a rule name, found {nameTok.Describe()}");

        var rb = _rb = new RuleBuilder(nameTok.Text, nameTok.Line);
        if (_ruleIndex.ContainsKey(rb.Name) || _failedRules.Contains(rb.Name))
            rb.Fail(nameTok.Line, "duplicate rule name");

        var tags = new List<string>();
        if (_lex.Peek().IsPunct(":"))
        {
            _lex.Next();
            while (_lex.Peek().Kind == TokenKind.Identifier && !YaraLexer.Keywords.Contains(_lex.Peek().Text))
            {
                var tag = _lex.Next().Text;
                if (!tags.Contains(tag)) tags.Add(tag);
            }
            if (tags.Count == 0) throw new YaraSyntaxException(_lex.Line, "expected at least one tag after ':'");
        }
        ExpectPunct("{");

        var meta = new Dictionary<string, string>(StringComparer.Ordinal);
        if (_lex.Peek().IsWord("meta"))
        {
            _lex.Next();
            ExpectPunct(":");
            while (_lex.Peek().Kind == TokenKind.Identifier && !_lex.Peek().IsWord("strings") && !_lex.Peek().IsWord("condition"))
                ParseMeta(meta);
        }

        if (_lex.Peek().IsWord("strings"))
        {
            _lex.Next();
            ExpectPunct(":");
            if (_lex.Peek().Kind != TokenKind.StringId) throw new YaraSyntaxException(_lex.Line, "the strings section is empty");
            while (_lex.Peek().Kind == TokenKind.StringId) ParseStringDefinition();
        }

        ExpectWord("condition");
        ExpectPunct(":");
        YExpr condition;
        try
        {
            condition = ParseExpression();
        }
        catch (RuleAbortException ex)
        {
            rb.Fail(ex.Line, ex.Message);
            condition = new UnknownExpr();
            while (_lex.Peek().Kind != TokenKind.End && !_lex.Peek().IsPunct("}")) _lex.Next();
        }
        ExpectPunct("}");

        for (var i = 0; i < rb.Strings.Count; i++)
        {
            var id = rb.Strings[i].Identifier;
            if (!rb.Referenced.Contains(i) && !id.StartsWith("$_", StringComparison.Ordinal))
                rb.Fail(rb.StringLines[i], id == "$" ? "an anonymous string is never used (reference it with 'them' or '$*')" : $"string {id} is never used in the condition");
        }

        if (rb.Error is not null)
        {
            _errors.Add($"{origin}:{rb.ErrorLine}: rule {rb.Name}: {rb.Error}");
            _failedRules.Add(rb.Name);
            return;
        }
        _ruleIndex[rb.Name] = _rules.Count;
        _rules.Add(new YaraRule(rb.Name, origin, rb.Line, isPrivate, isGlobal, tags, meta, [.. rb.Strings], condition, rb.MaxSlots));
    }

    private void ParseMeta(Dictionary<string, string> meta)
    {
        var key = _lex.Next();
        ExpectPunct("=");
        var v = _lex.Next();
        string value;
        if (v.Kind == TokenKind.Text)
        {
            value = YaraEscapes.ToText(v.Text, out var error);
            if (error is not null) _rb.Fail(v.Line, $"meta {key.Text}: {error}");
        }
        else if (v.Kind == TokenKind.Number) value = v.Number.ToString(CultureInfo.InvariantCulture);
        else if (v.IsPunct("-") && _lex.Peek().Kind == TokenKind.Number) value = (-_lex.Next().Number).ToString(CultureInfo.InvariantCulture);
        else if (v.IsWord("true") || v.IsWord("false")) value = v.Text;
        else throw new YaraSyntaxException(v.Line, $"expected a text, number or true/false value for meta '{key.Text}', found {v.Describe()}");
        meta.TryAdd(key.Text, value);
    }

    private void ParseStringDefinition()
    {
        var idTok = _lex.Next();
        ExpectPunct("=");
        var value = _lex.ReadStringValue();
        var mods = new StringModifiers();
        while (_lex.Peek().Kind == TokenKind.Identifier && Modifiers.Contains(_lex.Peek().Text))
        {
            var m = _lex.Next();
            if (!mods.Flags.Add(m.Text)) _rb.Fail(m.Line, $"string {idTok.Text}: duplicate modifier '{m.Text}'");
            if (m.Text == "xor" && _lex.Peek().IsPunct("("))
            {
                _lex.Next();
                var lo = ExpectNumber();
                var hi = lo;
                if (_lex.Peek().IsPunct("-"))
                {
                    _lex.Next();
                    hi = ExpectNumber();
                }
                ExpectPunct(")");
                if (lo is < 0 or > 255 || hi is < 0 or > 255 || lo > hi) _rb.Fail(m.Line, $"string {idTok.Text}: xor keys must be a range within 0-255");
                mods.XorMin = (int)Math.Clamp(lo, 0, 255);
                mods.XorMax = (int)Math.Clamp(hi, 0, 255);
            }
            else if (m.Text is "base64" or "base64wide" && _lex.Peek().IsPunct("("))
            {
                _lex.Next();
                var alphabetTok = Expect(TokenKind.Text, "a base64 alphabet in quotes");
                ExpectPunct(")");
                try
                {
                    var alphabet = YaraStringFactory.ParseAlphabet(alphabetTok.Text);
                    if (mods.Base64Alphabet is not null && !mods.Base64Alphabet.AsSpan().SequenceEqual(alphabet))
                        _rb.Fail(m.Line, $"string {idTok.Text}: base64 and base64wide must use the same alphabet");
                    mods.Base64Alphabet = alphabet;
                }
                catch (FormatException ex)
                {
                    _rb.Fail(m.Line, $"string {idTok.Text}: {ex.Message}");
                }
            }
        }

        var name = idTok.Text;
        if (name != "$" && _rb.StringIndex.ContainsKey(name)) _rb.Fail(idTok.Line, $"duplicate string identifier {name}");
        if (_rb.Error is not null)
        {
            // Keep the identifier known so the condition parses, but do not build anything.
            AddString(name, new PatternString(name, true, [], false), idTok.Line);
            return;
        }
        try
        {
            AddString(name, YaraStringFactory.Create(name, value, mods), idTok.Line);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or NotSupportedException)
        {
            _rb.Fail(value.Line, $"string {name}: {ex.Message}");
            AddString(name, new PatternString(name, true, [], false), idTok.Line);
        }
    }

    private void AddString(string name, YaraString str, int line)
    {
        if (name != "$") _rb.StringIndex.TryAdd(name, _rb.Strings.Count);
        _rb.Strings.Add(str);
        _rb.StringLines.Add(line);
    }

    // ---- expressions ------------------------------------------------------------------

    private void Enter(int line)
    {
        if (++_rb.Depth > YaraLimits.MaxNestingDepth)
            throw new RuleAbortException(line, $"condition nested more than {YaraLimits.MaxNestingDepth} levels deep");
    }

    private void Leave() => _rb.Depth--;

    private T Checked<T>(T node, int line) where T : YExpr
    {
        if (node.Depth > YaraLimits.MaxExpressionDepth)
            throw new RuleAbortException(line, $"condition is too complex (more than {YaraLimits.MaxExpressionDepth} levels of operators)");
        return node;
    }

    private YExpr ParseExpression()
    {
        Enter(_lex.Line);
        var e = ParseOr();
        Leave();
        return e;
    }

    private YExpr ParseOr()
    {
        var first = ParseAnd();
        if (!_lex.Peek().IsWord("or")) return first;
        var items = new List<YExpr> { first };
        while (_lex.Peek().IsWord("or"))
        {
            _lex.Next();
            items.Add(ParseAnd());
        }
        return Checked(new OrExpr(items), _lex.Line);
    }

    private YExpr ParseAnd()
    {
        var first = ParseNot();
        if (!_lex.Peek().IsWord("and")) return first;
        var items = new List<YExpr> { first };
        while (_lex.Peek().IsWord("and"))
        {
            _lex.Next();
            items.Add(ParseNot());
        }
        return Checked(new AndExpr(items), _lex.Line);
    }

    private YExpr ParseNot()
    {
        var t = _lex.Peek();
        if (t.IsWord("not") || t.IsWord("defined"))
        {
            _lex.Next();
            Enter(t.Line);
            var operand = ParseNot();
            Leave();
            return Checked<YExpr>(t.Text == "not" ? new NotExpr(operand) : new DefinedExpr(operand), t.Line);
        }
        return ParseEquality();
    }

    private YExpr ParseEquality()
    {
        var left = ParseRelational();
        while (true)
        {
            var t = _lex.Peek();
            if (t.IsPunct("==") || t.IsPunct("!="))
            {
                _lex.Next();
                var right = ParseRelational();
                if ((left.Type == YType.Bool && right.Type == YType.Int) || (left.Type == YType.Int && right.Type == YType.Bool))
                    _rb.Fail(t.Line, $"'{t.Text}' compares a boolean with an integer");
                left = Checked(new CompareExpr(t.Text, left, right), t.Line);
            }
            else if (t.Kind == TokenKind.Identifier && StringOperators.Contains(t.Text))
            {
                _lex.Next();
                if (t.Text == "matches") _lex.ReadRegexOperand();
                else ParseRelational();
                _rb.Fail(t.Line, $"the string operator '{t.Text}' is not supported (it needs string values, which only modules and external variables provide)");
                left = new UnknownExpr();
            }
            else return left;
        }
    }

    private YExpr ParseRelational()
    {
        var left = ParseBinary(0);
        while (true)
        {
            var t = _lex.Peek();
            if (t.Kind != TokenKind.Punct || t.Text is not ("<" or "<=" or ">" or ">=")) return left;
            _lex.Next();
            var right = ParseBinary(0);
            RequireInt(left, t);
            RequireInt(right, t);
            left = Checked(new CompareExpr(t.Text, left, right), t.Line);
        }
    }

    /// <summary>Integer operators from loosest to tightest binding, as in YARA's grammar.</summary>
    private static readonly string[][] BinaryLevels =
    [
        ["|"],
        ["^"],
        ["&"],
        ["<<", ">>"],
        ["+", "-"],
        ["*", "\\", "%"],
    ];

    private YExpr ParseBinary(int level)
    {
        if (level == BinaryLevels.Length) return ParseUnary();
        var left = ParseBinary(level + 1);
        while (true)
        {
            var t = _lex.Peek();
            if (t.Kind != TokenKind.Punct || Array.IndexOf(BinaryLevels[level], t.Text) < 0) return left;
            _lex.Next();
            var right = ParseBinary(level + 1);
            RequireInt(left, t);
            RequireInt(right, t);
            left = Checked(new ArithExpr(t.Text, left, right), t.Line);
        }
    }

    /// <summary>The operand of <c>at</c> and range bounds: an integer expression without comparisons.</summary>
    private YExpr ParseIntOperand()
    {
        var t = _lex.Peek();
        var e = ParseBinary(0);
        RequireInt(e, t);
        return e;
    }

    private YExpr ParseUnary()
    {
        var t = _lex.Peek();
        if (t.IsPunct("-") || t.IsPunct("~"))
        {
            _lex.Next();
            Enter(t.Line);
            var operand = ParseUnary();
            Leave();
            RequireInt(operand, t);
            return Checked(new UnaryExpr(t.Text[0], operand), t.Line);
        }
        return ParsePrimary();
    }

    private void RequireInt(YExpr e, Token op)
    {
        if (e.Type == YType.Bool) _rb.Fail(op.Line, $"'{op.Text}' needs integer operands, not a boolean");
    }

    private YExpr ParsePrimary()
    {
        var t = _lex.Peek();
        switch (t.Kind)
        {
            case TokenKind.Number:
                _lex.Next();
                if (_lex.Peek().IsPunct("%") && _lex.Peek(1).IsWord("of"))
                {
                    _lex.Next();
                    if (t.Number is < 1 or > 100) _rb.Fail(t.Line, "a percentage must be between 1 and 100");
                    return ParseOf(new Quantifier(QuantKind.Percent, percent: t.Number), t);
                }
                if (_lex.Peek().IsWord("of")) return ParseOf(new Quantifier(QuantKind.Count, new ConstExpr(YVal.Int(t.Number), YType.Int)), t);
                return new ConstExpr(YVal.Int(t.Number), YType.Int);

            case TokenKind.Text:
                _lex.Next();
                _rb.Fail(t.Line, "text strings in conditions only work with string operators, which are not supported");
                return new UnknownExpr();

            case TokenKind.StringId:
                {
                    _lex.Next();
                    var index = ResolveString(t);
                    if (_lex.Peek().IsWord("at"))
                    {
                        _lex.Next();
                        return Checked(new StringMatchExpr(index, ParseIntOperand(), null, null), t.Line);
                    }
                    if (_lex.Peek().IsWord("in"))
                    {
                        _lex.Next();
                        var (lo, hi) = ParseRange();
                        return Checked(new StringMatchExpr(index, null, lo, hi), t.Line);
                    }
                    return new StringMatchExpr(index, null, null, null);
                }

            case TokenKind.StringCount:
                {
                    _lex.Next();
                    var index = ResolveString(t);
                    if (_lex.Peek().IsWord("in"))
                    {
                        _lex.Next();
                        var (lo, hi) = ParseRange();
                        return Checked(new StringCountExpr(index, lo, hi), t.Line);
                    }
                    return new StringCountExpr(index, null, null);
                }

            case TokenKind.StringOffset or TokenKind.StringLength:
                {
                    _lex.Next();
                    var index = ResolveString(t);
                    YExpr which = new ConstExpr(YVal.Int(1), YType.Int);
                    if (_lex.Peek().IsPunct("["))
                    {
                        _lex.Next();
                        which = ParseExpression();
                        RequireInt(which, t);
                        ExpectPunct("]");
                    }
                    return Checked(new StringOccurrenceExpr(index, which, t.Kind == TokenKind.StringLength), t.Line);
                }

            case TokenKind.StringWildcard:
                throw new YaraSyntaxException(t.Line, $"'{t.Text}*' is only valid inside a set such as 'any of ({t.Text}*)'");

            case TokenKind.Punct when t.Text == "(":
                {
                    _lex.Next();
                    var e = ParseExpression();
                    ExpectPunct(")");
                    return e;
                }

            case TokenKind.Identifier:
                return ParseIdentifier(t);
        }
        throw new YaraSyntaxException(t.Line, $"unexpected {t.Describe()} in condition");
    }

    private YExpr ParseIdentifier(Token t)
    {
        switch (t.Text)
        {
            case "true" or "false":
                _lex.Next();
                return new ConstExpr(YVal.Bool(t.Text == "true"), YType.Bool);
            case "filesize":
                _lex.Next();
                return new FilesizeExpr();
            case "entrypoint":
                _lex.Next();
                _rb.Fail(t.Line, "'entrypoint' is not supported (it is deprecated in YARA; its replacement needs the pe module)");
                return new UnknownExpr();
            case "any" or "all" or "none":
                _lex.Next();
                return ParseOf(new Quantifier(t.Text switch { "any" => QuantKind.Any, "all" => QuantKind.All, _ => QuantKind.None }), t);
            case "for":
                return ParseFor();
            case "uint8" or "uint16" or "uint32" or "int8" or "int16" or "int32" or "uint8be" or "uint16be" or "uint32be" or "int8be" or "int16be" or "int32be":
                {
                    _lex.Next();
                    ExpectPunct("(");
                    var offset = ParseExpression();
                    RequireInt(offset, t);
                    ExpectPunct(")");
                    var name = t.Text;
                    var bigEndian = name.EndsWith("be", StringComparison.Ordinal);
                    var signed = !name.StartsWith('u');
                    var size = name.Contains("32", StringComparison.Ordinal) ? 4 : name.Contains("16", StringComparison.Ordinal) ? 2 : 1;
                    return Checked(new ReadIntExpr(size, signed, bigEndian, offset), t.Line);
                }
        }
        if (YaraLexer.Keywords.Contains(t.Text)) throw new YaraSyntaxException(t.Line, $"unexpected '{t.Text}' in condition");

        _lex.Next();
        var slot = _rb.Vars.FindLastIndex(v => v.Name == t.Text);
        if (slot >= 0) return new VarExpr(_rb.Vars[slot].Slot);

        var next = _lex.Peek();
        if (next.IsPunct(".") || next.IsPunct("[") || next.IsPunct("("))
        {
            SkipModuleAccess();
            _rb.Fail(t.Line, KnownModules.Contains(t.Text)
                ? $"uses the '{t.Text}' module, which is not supported"
                : $"uses '{t.Text}', an unknown module or function");
            return new UnknownExpr();
        }
        if (_ruleIndex.TryGetValue(t.Text, out var ruleIndex)) return new RuleRefExpr(ruleIndex);
        if (_failedRules.Contains(t.Text)) _rb.Fail(t.Line, $"references rule {t.Text}, which could not be compiled");
        else _rb.Fail(t.Line, $"undefined identifier '{t.Text}' (rules must be defined before they are referenced; external variables are not supported)");
        return new UnknownExpr();
    }

    /// <summary>Consumes <c>.field</c>, <c>[index]</c> and <c>(args)</c> after a module name so the rule can be skipped cleanly.</summary>
    private void SkipModuleAccess()
    {
        while (true)
        {
            var t = _lex.Peek();
            if (t.IsPunct("."))
            {
                _lex.Next();
                Expect(TokenKind.Identifier, "a field name");
            }
            else if (t.IsPunct("["))
            {
                _lex.Next();
                ParseExpression();
                ExpectPunct("]");
            }
            else if (t.IsPunct("("))
            {
                _lex.Next();
                if (_lex.Peek().IsPunct(")")) { _lex.Next(); continue; }
                while (true)
                {
                    if (_lex.RawNextIs('/')) _lex.ReadRegexOperand();
                    else ParseExpression();
                    if (_lex.Peek().IsPunct(",")) { _lex.Next(); continue; }
                    ExpectPunct(")");
                    break;
                }
            }
            else return;
        }
    }

    private int ResolveString(Token t)
    {
        var name = "$" + t.Text[1..];
        if (name == "$")
        {
            if (_rb.ForOfDepth == 0) _rb.Fail(t.Line, $"'{t.Text}' without a name is only valid inside 'for ... of'");
            return -1;
        }
        if (_rb.StringIndex.TryGetValue(name, out var index))
        {
            _rb.Referenced.Add(index);
            return index;
        }
        _rb.Fail(t.Line, $"undefined string {name}");
        return -1;
    }

    private (YExpr Lo, YExpr Hi) ParseRange()
    {
        ExpectPunct("(");
        var lo = ParseIntOperand();
        ExpectPunct("..");
        var hi = ParseIntOperand();
        ExpectPunct(")");
        return (lo, hi);
    }

    private YExpr ParseOf(Quantifier quant, Token start)
    {
        ExpectWord("of");
        var (items, rules) = ParseSet(start);
        if (quant.Kind == QuantKind.All && items.Length == 0) _rb.Fail(start.Line, "the set is empty");
        YExpr? at = null, lo = null, hi = null;
        if (!rules && _lex.Peek().IsWord("at"))
        {
            _lex.Next();
            at = ParseIntOperand();
        }
        else if (!rules && _lex.Peek().IsWord("in"))
        {
            _lex.Next();
            (lo, hi) = ParseRange();
        }
        return Checked(new OfExpr(quant, items, rules, at, lo, hi), start.Line);
    }

    /// <summary>them | ($a, $b*, $*) | (rule_a, rule_b*). Returns local string or rule indices.</summary>
    private (int[] Items, bool Rules) ParseSet(Token start)
    {
        if (_lex.Peek().IsWord("them"))
        {
            _lex.Next();
            if (_rb.Strings.Count == 0) _rb.Fail(start.Line, "'them' is used in a rule without strings");
            for (var i = 0; i < _rb.Strings.Count; i++) _rb.Referenced.Add(i);
            return (Enumerable.Range(0, _rb.Strings.Count).ToArray(), false);
        }

        ExpectPunct("(");
        var strings = new List<int>();
        var rules = new List<int>();
        while (true)
        {
            var t = _lex.Next();
            if (t.Kind == TokenKind.StringId)
            {
                if (t.Text == "$") throw new YaraSyntaxException(t.Line, "an anonymous '$' cannot be listed in a set; use '$*' or 'them'");
                var index = ResolveString(t);
                if (index >= 0) strings.Add(index);
            }
            else if (t.Kind == TokenKind.StringWildcard)
            {
                var found = false;
                for (var i = 0; i < _rb.Strings.Count; i++)
                {
                    if (!_rb.Strings[i].Identifier.StartsWith(t.Text, StringComparison.Ordinal)) continue;
                    strings.Add(i);
                    _rb.Referenced.Add(i);
                    found = true;
                }
                if (!found) _rb.Fail(t.Line, $"no string matches '{t.Text}*'");
            }
            else if (t.Kind == TokenKind.Identifier && !YaraLexer.Keywords.Contains(t.Text))
            {
                if (_lex.Peek().IsPunct("*"))
                {
                    _lex.Next();
                    var matched = _ruleIndex.Where(kv => kv.Key.StartsWith(t.Text, StringComparison.Ordinal)).Select(kv => kv.Value).ToList();
                    if (matched.Count == 0) _rb.Fail(t.Line, $"no earlier rule matches '{t.Text}*'");
                    rules.AddRange(matched);
                }
                else if (_ruleIndex.TryGetValue(t.Text, out var r)) rules.Add(r);
                else if (_failedRules.Contains(t.Text)) _rb.Fail(t.Line, $"references rule {t.Text}, which could not be compiled");
                else _rb.Fail(t.Line, $"undefined rule '{t.Text}' in set (rules must be defined before they are referenced)");
            }
            else throw new YaraSyntaxException(t.Line, $"expected a string or rule in the set, found {t.Describe()}");

            if (_lex.Peek().IsPunct(",")) { _lex.Next(); continue; }
            ExpectPunct(")");
            break;
        }
        if (strings.Count > 0 && rules.Count > 0) _rb.Fail(start.Line, "a set cannot mix strings and rules");
        return rules.Count > 0 ? (rules.Distinct().ToArray(), true) : (strings.Distinct().ToArray(), false);
    }

    private YExpr ParseFor()
    {
        var forTok = _lex.Next();
        Enter(forTok.Line);
        Quantifier quant;
        var q = _lex.Next();
        if (q.IsWord("any")) quant = new Quantifier(QuantKind.Any);
        else if (q.IsWord("all")) quant = new Quantifier(QuantKind.All);
        else if (q.IsWord("none")) quant = new Quantifier(QuantKind.None);
        else if (q.Kind == TokenKind.Number)
        {
            if (_lex.Peek().IsPunct("%"))
            {
                _lex.Next();
                if (q.Number is < 1 or > 100) _rb.Fail(q.Line, "a percentage must be between 1 and 100");
                quant = new Quantifier(QuantKind.Percent, percent: q.Number);
            }
            else quant = new Quantifier(QuantKind.Count, new ConstExpr(YVal.Int(q.Number), YType.Int));
        }
        else throw new YaraSyntaxException(q.Line, $"expected any, all, none or a number after 'for', found {q.Describe()}");

        YExpr result;
        if (_lex.Peek().IsWord("of"))
        {
            _lex.Next();
            var (items, rules) = ParseSet(forTok);
            if (rules) _rb.Fail(forTok.Line, "'for ... of' over rules is not supported");
            ExpectPunct(":");
            ExpectPunct("(");
            _rb.ForOfDepth++;
            var body = ParseExpression();
            _rb.ForOfDepth--;
            ExpectPunct(")");
            result = new ForOfExpr(quant, items, body);
        }
        else
        {
            var names = new List<Token> { Expect(TokenKind.Identifier, "a loop variable") };
            while (_lex.Peek().IsPunct(","))
            {
                _lex.Next();
                names.Add(Expect(TokenKind.Identifier, "a loop variable"));
            }
            if (names.Count > 1) _rb.Fail(forTok.Line, "loops with several variables iterate module dictionaries, which are not supported");
            ExpectWord("in");

            YExpr? lo = null, hi = null;
            List<YExpr>? values = null;
            if (_lex.Peek().IsPunct("("))
            {
                _lex.Next();
                var first = ParseIntOperand();
                if (_lex.Peek().IsPunct(".."))
                {
                    _lex.Next();
                    lo = first;
                    hi = ParseIntOperand();
                }
                else
                {
                    values = [first];
                    while (_lex.Peek().IsPunct(","))
                    {
                        _lex.Next();
                        values.Add(ParseIntOperand());
                    }
                }
                ExpectPunct(")");
            }
            else if (_lex.Peek().Kind == TokenKind.Identifier)
            {
                var module = _lex.Next();
                SkipModuleAccess();
                _rb.Fail(module.Line, $"loops over '{module.Text}' need modules, which are not supported");
                lo = hi = new ConstExpr(YVal.Int(0), YType.Int);
            }
            else throw new YaraSyntaxException(_lex.Line, "expected a range '(a..b)' or a list '(a, b, c)' after 'in'");

            ExpectPunct(":");
            ExpectPunct("(");
            var slot = _rb.Vars.Count;
            _rb.Vars.Add((names[0].Text, slot));
            _rb.MaxSlots = Math.Max(_rb.MaxSlots, _rb.Vars.Count);
            var body = ParseExpression();
            _rb.Vars.RemoveAt(_rb.Vars.Count - 1);
            ExpectPunct(")");
            result = new ForInExpr(quant, slot, lo, hi, values, body);
        }
        Leave();
        return Checked(result, forTok.Line);
    }

    // ---- helpers ----------------------------------------------------------------------

    private Token Expect(TokenKind kind, string what)
    {
        var t = _lex.Next();
        if (t.Kind != kind) throw new YaraSyntaxException(t.Line, $"expected {what}, found {t.Describe()}");
        return t;
    }

    private void ExpectPunct(string p)
    {
        var t = _lex.Next();
        if (!t.IsPunct(p)) throw new YaraSyntaxException(t.Line, $"expected '{p}', found {t.Describe()}");
    }

    private void ExpectWord(string w)
    {
        var t = _lex.Next();
        if (!t.IsWord(w)) throw new YaraSyntaxException(t.Line, $"expected '{w}', found {t.Describe()}");
    }

    private long ExpectNumber() => Expect(TokenKind.Number, "a number").Number;
}
