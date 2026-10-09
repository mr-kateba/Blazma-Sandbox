using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Blazma.Analysis.Yara;

/// <summary>
/// Translates YARA's regex dialect into a .NET pattern run with
/// <see cref="RegexOptions.NonBacktracking"/> (linear time, so no rule can hang a scan).
/// The pattern is parsed into a small tree first so every construct is checked: anything
/// YARA does not have (backreferences, lookarounds, inline options) is an error, and
/// classes and nocase are expanded over bytes here rather than trusting .NET's
/// Unicode-aware classes. Wide strings run the same pattern over a view of UTF-16 units.
/// </summary>
internal static class YaraRegex
{
    /// <summary>
    /// Data is viewed as text one byte per char. Bytes 0x80-0xFF map to U+2580-U+25FF
    /// (symbols with no case, not letters, digits or spaces) instead of Latin-1, so .NET's
    /// <c>\b</c> treats them as YARA does: as non-word characters.
    /// </summary>
    public static char MapByte(int b) => (char)(b < 0x80 ? b : b + 0x2500);

    public static string ByteView(ReadOnlySpan<byte> data) =>
        string.Create(data.Length, data, static (chars, bytes) =>
        {
            for (var i = 0; i < bytes.Length; i++) chars[i] = MapByte(bytes[i]);
        });

    /// <summary>
    /// Wide data viewed one char per 2-byte unit, so the same regex (and its \b, ^ and $)
    /// works on UTF-16 text. Char j covers bytes 2j-<paramref name="alignment"/> and the
    /// next; a unit whose second byte is not zero, or that is cut off at either end,
    /// becomes U+FFFF, which no byte class contains.
    /// </summary>
    public static string WideView(ReadOnlySpan<byte> data, int alignment) =>
        string.Create((data.Length + alignment + 1) / 2, new WideSource(data, alignment), static (chars, src) =>
        {
            for (var j = 0; j < chars.Length; j++)
            {
                var lo = 2 * j - src.Alignment;
                chars[j] = lo < 0 || lo + 1 >= src.Data.Length || src.Data[lo + 1] != 0 ? '\uFFFF' : MapByte(src.Data[lo]);
            }
        });

    private readonly ref struct WideSource(ReadOnlySpan<byte> data, int alignment)
    {
        public ReadOnlySpan<byte> Data { get; } = data;
        public int Alignment { get; } = alignment;
    }

    /// <summary>
    /// A compiled regex variant, the literal every match must contain (a cheap prefilter),
    /// and whether it uses ^ or $, which only mean something over the whole data.
    /// </summary>
    public sealed record Compiled(Regex Regex, BytePattern? Required, bool Anchored);

    public static Compiled Compile(string pattern, bool nocase, bool dotAll, bool wide)
    {
        var parser = new Parser(pattern, nocase, dotAll);
        var tree = parser.Parse();
        var sb = new StringBuilder();
        Emit(tree, sb);
        // No match timeout: every call runs over a bounded window, and .NET's non-backtracking
        // engine was seen to miss \b matches on large inputs when a timeout is set.
        var regex = new Regex(sb.ToString(), RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);
        return new Compiled(regex, RequiredLiteral(tree, nocase, wide), HasEdgeAnchor(tree));
    }

    // ---- tree -------------------------------------------------------------------------

    private abstract class Node;

    /// <summary>One byte from a set; literals are one-element (or, with nocase, two-element) sets.</summary>
    private sealed class ByteSet(bool[] members, bool literal) : Node
    {
        public bool[] Members { get; } = members;
        public bool IsLiteral { get; } = literal;
    }

    private sealed class Concat(List<Node> items) : Node
    {
        public List<Node> Items { get; } = items;
    }

    private sealed class Alternation(List<Node> branches) : Node
    {
        public List<Node> Branches { get; } = branches;
    }

    private sealed class Repeat(Node body, int min, int max, bool lazy) : Node
    {
        public Node Body { get; } = body;
        public int Min { get; } = min;
        public int Max { get; } = max; // -1 = unbounded
        public bool Lazy { get; } = lazy;
    }

    private sealed class Anchor(string dotnet) : Node
    {
        public string DotNet { get; } = dotnet;
    }

    private sealed class Parser(string src, bool nocase, bool dotAll)
    {
        private int _pos;
        private int _depth;

        public Node Parse()
        {
            var node = ParseAlternation();
            if (_pos < src.Length) throw new FormatException($"unbalanced ')' at position {_pos + 1}");
            return node;
        }

        private Node ParseAlternation()
        {
            if (++_depth > YaraLimits.MaxNestingDepth) throw new FormatException($"regular expression nested more than {YaraLimits.MaxNestingDepth} levels");
            var branches = new List<Node> { ParseConcat() };
            while (_pos < src.Length && src[_pos] == '|')
            {
                _pos++;
                branches.Add(ParseConcat());
            }
            _depth--;
            return branches.Count == 1 ? branches[0] : new Alternation(branches);
        }

        private Node ParseConcat()
        {
            var items = new List<Node>();
            while (_pos < src.Length && src[_pos] is not ('|' or ')'))
            {
                var atom = ParseAtom();
                items.Add(ParseQuantifiers(atom));
            }
            return items.Count == 1 ? items[0] : new Concat(items);
        }

        private Node ParseQuantifiers(Node atom)
        {
            while (_pos < src.Length)
            {
                int min, max;
                var c = src[_pos];
                if (c == '*') { min = 0; max = -1; _pos++; }
                else if (c == '+') { min = 1; max = -1; _pos++; }
                else if (c == '?') { min = 0; max = 1; _pos++; }
                else if (c == '{' && TryParseBraces(out min, out max)) { }
                else break;

                if (atom is Anchor) throw new FormatException("a quantifier cannot follow an anchor");
                var lazy = false;
                if (_pos < src.Length && src[_pos] == '?') { lazy = true; _pos++; }
                atom = new Repeat(atom, min, max, lazy);
            }
            return atom;
        }

        /// <summary>{n} {n,} {,m} {n,m}; anything else leaves '{' as a literal, as in YARA.</summary>
        private bool TryParseBraces(out int min, out int max)
        {
            min = max = 0;
            var end = src.IndexOf('}', _pos);
            if (end < 0) return false;
            var body = src[(_pos + 1)..end];
            var comma = body.IndexOf(',', StringComparison.Ordinal);
            string lo = comma < 0 ? body : body[..comma], hi = comma < 0 ? body : body[(comma + 1)..];
            if ((lo.Length > 0 && !lo.All(char.IsAsciiDigit)) || (hi.Length > 0 && !hi.All(char.IsAsciiDigit))) return false;
            if (lo.Length == 0 && hi.Length == 0) return false;
            if (lo.Length > 6 || hi.Length > 6) throw new FormatException($"repetition {{{body}}} is too large (limit {YaraLimits.MaxRegexRepeat})");
            min = lo.Length == 0 ? 0 : int.Parse(lo, CultureInfo.InvariantCulture);
            max = hi.Length == 0 ? -1 : int.Parse(hi, CultureInfo.InvariantCulture);
            if (min > YaraLimits.MaxRegexRepeat || max > YaraLimits.MaxRegexRepeat)
                throw new FormatException($"repetition {{{body}}} is too large (limit {YaraLimits.MaxRegexRepeat})");
            if (max >= 0 && min > max) throw new FormatException($"bad repetition {{{body}}}");
            _pos = end + 1;
            return true;
        }

        private Node ParseAtom()
        {
            var c = src[_pos];
            switch (c)
            {
                case '(':
                    if (_pos + 1 < src.Length && src[_pos + 1] == '?')
                        throw new FormatException("'(?' constructs (lookarounds, named or non-capturing groups, inline options) are not supported by YARA");
                    _pos++;
                    var inner = ParseAlternation();
                    if (_pos >= src.Length || src[_pos] != ')') throw new FormatException("missing ')'");
                    _pos++;
                    return inner;
                case '[':
                    return ParseClass();
                case '.':
                    _pos++;
                    var any = new bool[256];
                    Array.Fill(any, true);
                    if (!dotAll) any['\n'] = false;
                    return new ByteSet(any, false);
                case '^':
                    _pos++;
                    return new Anchor("\\A");
                case '$':
                    _pos++;
                    return new Anchor("\\z");
                case '*' or '+' or '?':
                    throw new FormatException($"'{c}' has nothing to repeat");
                case '\\':
                    return ParseEscape();
                default:
                    if (c >= 0x80) throw new FormatException("non-ASCII characters in regular expressions are not supported; use \\xHH escapes");
                    _pos++;
                    return Literal((byte)c);
            }
        }

        private ByteSet Literal(byte b)
        {
            var set = new bool[256];
            set[b] = true;
            if (nocase) FoldCase(set);
            return new ByteSet(set, true);
        }

        private Node ParseEscape()
        {
            if (_pos + 1 >= src.Length) throw new FormatException("regular expression ends with '\\'");
            var e = src[_pos + 1];
            _pos += 2;
            switch (e)
            {
                case 'b': return new Anchor("\\b");
                case 'B': return new Anchor("\\B");
                case 'w' or 'W' or 's' or 'S' or 'd' or 'D':
                    {
                        var set = new bool[256];
                        AddShorthand(set, e);
                        return new ByteSet(set, false);
                    }
            }
            return Literal(EscapedByte(e));
        }

        /// <summary>The byte an escape such as \n, \x41 or \. stands for, inside or outside a class.</summary>
        private byte EscapedByte(char e)
        {
            switch (e)
            {
                case 'n': return (byte)'\n';
                case 't': return (byte)'\t';
                case 'r': return (byte)'\r';
                case 'f': return 0x0C;
                case 'a': return 0x07;
                case 'x':
                    if (_pos + 2 <= src.Length && byte.TryParse(src.AsSpan(_pos, 2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var v))
                    {
                        _pos += 2;
                        return v;
                    }
                    throw new FormatException("'\\x' must be followed by two hex digits");
            }
            if (char.IsAsciiDigit(e)) throw new FormatException($"backreferences ('\\{e}') are not supported");
            if (char.IsAsciiLetter(e)) throw new FormatException($"unknown escape '\\{e}'");
            if (e >= 0x80) throw new FormatException("non-ASCII characters in regular expressions are not supported; use \\xHH escapes");
            return (byte)e; // an escaped punctuation character stands for itself
        }

        private static void AddShorthand(bool[] set, char e)
        {
            var tmp = new bool[256];
            switch (char.ToLowerInvariant(e))
            {
                case 'w':
                    for (var b = 0; b < 256; b++) tmp[b] = char.IsAsciiLetterOrDigit((char)b) || b == '_';
                    break;
                case 'd':
                    for (var b = '0'; b <= '9'; b++) tmp[b] = true;
                    break;
                case 's':
                    foreach (var b in " \t\n\v\f\r") tmp[b] = true;
                    break;
            }
            var negate = char.IsUpper(e);
            for (var b = 0; b < 256; b++) if (tmp[b] != negate) set[b] = true;
        }

        private ByteSet ParseClass()
        {
            var start = _pos++;
            var negate = false;
            if (_pos < src.Length && src[_pos] == '^') { negate = true; _pos++; }
            var set = new bool[256];
            var first = true;
            while (true)
            {
                if (_pos >= src.Length) throw new FormatException($"unterminated character class starting at position {start + 1}");
                var c = src[_pos];
                if (c == ']' && !first) { _pos++; break; }
                first = false;

                int lo;
                if (c == '\\')
                {
                    if (_pos + 1 >= src.Length) throw new FormatException("unterminated character class");
                    var e = src[_pos + 1];
                    _pos += 2;
                    if (e is 'w' or 'W' or 's' or 'S' or 'd' or 'D') { AddShorthand(set, e); continue; }
                    if (e is 'b' or 'B') throw new FormatException("\\b is not allowed inside a character class");
                    lo = EscapedByte(e);
                }
                else
                {
                    if (c >= 0x80) throw new FormatException("non-ASCII characters in regular expressions are not supported; use \\xHH escapes");
                    if (c == '[' && _pos + 1 < src.Length && src[_pos + 1] == ':') throw new FormatException("POSIX character classes ([:alpha:]) are not supported");
                    lo = c;
                    _pos++;
                }

                var hi = lo;
                if (_pos + 1 < src.Length && src[_pos] == '-' && src[_pos + 1] != ']')
                {
                    _pos++;
                    var h = src[_pos];
                    if (h == '\\')
                    {
                        if (_pos + 1 >= src.Length) throw new FormatException("unterminated character class");
                        var e = src[_pos + 1];
                        _pos += 2;
                        if (e is 'w' or 'W' or 's' or 'S' or 'd' or 'D' or 'b' or 'B') throw new FormatException("a class shorthand cannot end a range");
                        hi = EscapedByte(e);
                    }
                    else
                    {
                        if (h >= 0x80) throw new FormatException("non-ASCII characters in regular expressions are not supported; use \\xHH escapes");
                        hi = h;
                        _pos++;
                    }
                    if (hi < lo) throw new FormatException($"bad character range {(char)lo}-{(char)hi}");
                }
                for (var b = lo; b <= hi; b++) set[b] = true;
            }
            if (nocase) FoldCase(set);
            if (negate) for (var b = 0; b < 256; b++) set[b] = !set[b];
            if (Array.IndexOf(set, true) < 0) throw new FormatException("character class matches nothing");
            return new ByteSet(set, false);
        }

        private static void FoldCase(bool[] set)
        {
            for (var b = 'A'; b <= 'Z'; b++)
            {
                var either = set[b] || set[b + 32];
                set[b] = set[b + 32] = either;
            }
        }
    }

    // ---- emitting ---------------------------------------------------------------------

    private static void Emit(Node node, StringBuilder sb)
    {
        switch (node)
        {
            case ByteSet set:
                EmitSet(set.Members, sb);
                break;
            case Concat c:
                foreach (var item in c.Items) Emit(item, sb);
                break;
            case Alternation a:
                sb.Append("(?:");
                for (var i = 0; i < a.Branches.Count; i++)
                {
                    if (i > 0) sb.Append('|');
                    Emit(a.Branches[i], sb);
                }
                sb.Append(')');
                break;
            case Repeat r:
                sb.Append("(?:");
                Emit(r.Body, sb);
                sb.Append(')');
                sb.Append(CultureInfo.InvariantCulture, $"{{{r.Min},{(r.Max < 0 ? string.Empty : r.Max.ToString(CultureInfo.InvariantCulture))}}}");
                if (r.Lazy) sb.Append('?');
                break;
            case Anchor anchor:
                sb.Append(anchor.DotNet);
                break;
        }
    }

    private static void EmitSet(bool[] members, StringBuilder sb)
    {
        var count = members.Count(m => m);
        if (count == 1)
        {
            AppendChar(sb, Array.IndexOf(members, true));
            return;
        }
        sb.Append('[');
        for (var b = 0; b < 256;)
        {
            if (!members[b]) { b++; continue; }
            var lo = b;
            // Ranges never cross 0x7F/0x80: the two halves map to different char blocks.
            while (b + 1 < 256 && members[b + 1] && b + 1 != 0x80) b++;
            AppendChar(sb, lo);
            if (b > lo) { sb.Append('-'); AppendChar(sb, b); }
            b++;
        }
        sb.Append(']');
    }

    private static void AppendChar(StringBuilder sb, int b) =>
        sb.Append(CultureInfo.InvariantCulture, $"\\u{(int)MapByte(b):X4}");

    private static bool HasEdgeAnchor(Node node) => node switch
    {
        Anchor a => a.DotNet is "\\A" or "\\z",
        Concat c => c.Items.Any(HasEdgeAnchor),
        Alternation a => a.Branches.Any(HasEdgeAnchor),
        Repeat r => HasEdgeAnchor(r.Body),
        _ => false,
    };

    /// <summary>
    /// The longest run of literal bytes every match must contain (top-level only). If the data
    /// does not contain it, the regex cannot match and is not run at all.
    /// </summary>
    private static BytePattern? RequiredLiteral(Node tree, bool nocase, bool wide)
    {
        var items = tree is Concat c ? c.Items : [tree];
        List<byte> best = [], current = [];
        foreach (var item in items)
        {
            if (item is ByteSet { IsLiteral: true } set)
            {
                current.Add((byte)Array.IndexOf(set.Members, true));
                if (current.Count > best.Count) best = [.. current];
                continue;
            }
            if (item is Repeat { Min: >= 1, Body: ByteSet { IsLiteral: true } rep })
            {
                // "ab+c" requires "ab" and "bc", but not "abc".
                var b = (byte)Array.IndexOf(rep.Members, true);
                current.Add(b);
                if (current.Count > best.Count) best = [.. current];
                current = [b];
                continue;
            }
            if (item is Anchor) continue;
            current = [];
        }
        if (best.Count < 2) return null;

        var bytes = wide ? best.SelectMany(b => new[] { b, (byte)0 }).ToArray() : [.. best];
        return nocase ? BytePattern.NoCase(bytes) : BytePattern.Exact(bytes);
    }
}
