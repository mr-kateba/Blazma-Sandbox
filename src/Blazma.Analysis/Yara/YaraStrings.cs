using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;

namespace Blazma.Analysis.Yara;

/// <summary>The byte view regexes run over, built once per scan and only if a regex needs it.</summary>
internal sealed class ByteViewCache
{
    private string? _view;
    private readonly string?[] _wide = new string?[2];

    public string Get(ReadOnlySpan<byte> data) => _view ??= YaraRegex.ByteView(data);

    public string GetWide(ReadOnlySpan<byte> data, int alignment) => _wide[alignment] ??= YaraRegex.WideView(data, alignment);
}

/// <summary>A string definition of a rule, compiled into something that can search bytes.</summary>
internal abstract class YaraString(string identifier, bool isPrivate)
{
    /// <summary>"$name", or "$" for an anonymous string.</summary>
    public string Identifier { get; } = identifier;

    public bool IsPrivate { get; } = isPrivate;

    /// <summary>Adds match starts in ascending order, at most <see cref="YaraLimits.MaxHitsPerString"/>.</summary>
    public abstract SearchOutcome Find(ReadOnlySpan<byte> data, ByteViewCache view, List<YaraHit> hits, long deadline);

    /// <summary>
    /// Merges the hits of several variants (ascii and wide, xor keys, base64 offsets) into one
    /// ordered list; one match per offset, as YARA keeps.
    /// </summary>
    protected static SearchOutcome MergeVariants(int variantCount, Func<int, List<YaraHit>, SearchOutcome> search, List<YaraHit> hits)
    {
        if (variantCount == 1) return search(0, hits);
        var all = new List<YaraHit>();
        var outcome = SearchOutcome.Complete;
        for (var i = 0; i < variantCount; i++)
        {
            var part = new List<YaraHit>();
            var o = search(i, part);
            if (o == SearchOutcome.TimedOut) outcome = o;
            all.AddRange(part);
        }
        all.Sort((a, b) => a.Offset.CompareTo(b.Offset));
        var last = -1;
        foreach (var h in all)
        {
            if (h.Offset == last) continue;
            if (hits.Count >= YaraLimits.MaxHitsPerString) return outcome == SearchOutcome.TimedOut ? outcome : SearchOutcome.Capped;
            hits.Add(h);
            last = h.Offset;
        }
        return outcome;
    }

    /// <summary>YARA's fullword: the bytes around the match (as wide characters for wide strings) are not alphanumeric.</summary>
    protected static bool IsFullword(ReadOnlySpan<byte> data, int start, int length, bool wide)
    {
        var end = start + length;
        if (wide)
        {
            if (start >= 2 && IsAlnum(data[start - 2]) && data[start - 1] == 0) return false;
            if (end + 1 < data.Length && IsAlnum(data[end]) && data[end + 1] == 0) return false;
            return true;
        }
        if (start > 0 && IsAlnum(data[start - 1])) return false;
        return end >= data.Length || !IsAlnum(data[end]);
    }

    private static bool IsAlnum(byte b) => char.IsAsciiLetterOrDigit((char)b);

    public static byte[] Widen(byte[] bytes)
    {
        var wide = new byte[bytes.Length * 2];
        for (var i = 0; i < bytes.Length; i++) wide[i * 2] = bytes[i];
        return wide;
    }
}

/// <summary>Fixed byte patterns: text strings (ascii, wide, nocase, fullword), base64 forms and simple hex strings.</summary>
internal sealed class PatternString(string identifier, bool isPrivate, IReadOnlyList<(BytePattern Pattern, bool Wide)> variants, bool fullword)
    : YaraString(identifier, isPrivate)
{
    public override SearchOutcome Find(ReadOnlySpan<byte> data, ByteViewCache view, List<YaraHit> hits, long deadline)
    {
        // A span cannot be captured by the merge callback, so each variant is searched first.
        var results = new List<YaraHit>[variants.Count];
        var timedOut = false;
        for (var v = 0; v < variants.Count; v++)
        {
            results[v] = [];
            var (pattern, wide) = variants[v];
            var pos = 0;
            while (results[v].Count < YaraLimits.MaxHitsPerString)
            {
                var at = pattern.FindNext(data, pos, deadline);
                if (at == -2) { timedOut = true; break; }
                if (at < 0) break;
                if (!fullword || IsFullword(data, at, pattern.Length, wide)) results[v].Add(new YaraHit(at, pattern.Length));
                pos = at + 1;
            }
        }
        var outcome = MergeVariants(results.Length, (i, list) =>
        {
            list.AddRange(results[i]);
            return list.Count >= YaraLimits.MaxHitsPerString ? SearchOutcome.Capped : SearchOutcome.Complete;
        }, hits);
        return timedOut ? SearchOutcome.TimedOut : outcome;
    }
}

/// <summary>
/// Text strings with the xor modifier. Few keys are expanded into plain patterns; for wider
/// key ranges the data is scanned once using the fact that XOR of two neighbouring bytes
/// does not depend on the key, then each candidate's key is recovered and checked.
/// </summary>
internal sealed class XorString(string identifier, bool isPrivate, IReadOnlyList<byte[]> plains, int minKey, int maxKey)
    : YaraString(identifier, isPrivate)
{
    public override SearchOutcome Find(ReadOnlySpan<byte> data, ByteViewCache view, List<YaraHit> hits, long deadline)
    {
        var results = new List<YaraHit>[plains.Count];
        var timedOut = false;
        for (var v = 0; v < plains.Count; v++)
        {
            results[v] = [];
            if (Scan(data, plains[v], results[v], deadline) == SearchOutcome.TimedOut) timedOut = true;
        }
        var outcome = MergeVariants(results.Length, (i, list) =>
        {
            list.AddRange(results[i]);
            return SearchOutcome.Complete;
        }, hits);
        return timedOut ? SearchOutcome.TimedOut : outcome;
    }

    private SearchOutcome Scan(ReadOnlySpan<byte> data, byte[] plain, List<YaraHit> hits, long deadline)
    {
        var length = plain.Length;
        if (maxKey - minKey < 4)
        {
            // Expand: one exact pattern per key, merged in offset order.
            var perKey = new List<YaraHit>();
            for (var key = minKey; key <= maxKey; key++)
            {
                var pattern = BytePattern.Exact(plain.Select(b => (byte)(b ^ key)).ToArray());
                var pos = 0;
                var found = 0;
                while (found < YaraLimits.MaxHitsPerString)
                {
                    var at = pattern.FindNext(data, pos, deadline);
                    if (at == -2) return SearchOutcome.TimedOut;
                    if (at < 0) break;
                    perKey.Add(new YaraHit(at, length));
                    found++;
                    pos = at + 1;
                }
            }
            perKey.Sort((a, b) => a.Offset.CompareTo(b.Offset));
            hits.AddRange(perKey.DistinctBy(h => h.Offset).Take(YaraLimits.MaxHitsPerString));
            return SearchOutcome.Complete;
        }

        var last = data.Length - length;
        if (length == 1)
        {
            for (var i = 0; i <= last && hits.Count < YaraLimits.MaxHitsPerString; i++)
            {
                var key = data[i] ^ plain[0];
                if (key >= minKey && key <= maxKey) hits.Add(new YaraHit(i, 1));
            }
            return SearchOutcome.Complete;
        }

        var pair = (byte)(plain[0] ^ plain[1]);
        var target = new Vector<byte>(pair);
        var width = Vector<byte>.Count;
        var i2 = 0;
        var blocks = 0;
        while (i2 <= last && hits.Count < YaraLimits.MaxHitsPerString)
        {
            if (i2 + width + 1 <= data.Length)
            {
                var a = new Vector<byte>(data.Slice(i2, width));
                var b = new Vector<byte>(data.Slice(i2 + 1, width));
                if (!Vector.EqualsAny(a ^ b, target))
                {
                    i2 += width;
                    if (++blocks % 65536 == 0 && YaraClock.Now > deadline) return SearchOutcome.TimedOut;
                    continue;
                }
                var stop = Math.Min(i2 + width, last + 1);
                for (; i2 < stop && hits.Count < YaraLimits.MaxHitsPerString; i2++) Check(data, plain, i2, pair, hits);
                continue;
            }
            Check(data, plain, i2, pair, hits);
            i2++;
        }
        return SearchOutcome.Complete;
    }

    private void Check(ReadOnlySpan<byte> data, byte[] plain, int i, byte pair, List<YaraHit> hits)
    {
        if ((byte)(data[i] ^ data[i + 1]) != pair) return;
        var key = data[i] ^ plain[0];
        if (key < minKey || key > maxKey) return;
        for (var j = 2; j < plain.Length; j++)
            if ((data[i + j] ^ key) != plain[j]) return;
        hits.Add(new YaraHit(i, plain.Length));
    }
}

/// <summary>Hex strings with variable jumps or alternatives.</summary>
internal sealed class HexString(string identifier, bool isPrivate, HexProgram program) : YaraString(identifier, isPrivate)
{
    public override SearchOutcome Find(ReadOnlySpan<byte> data, ByteViewCache view, List<YaraHit> hits, long deadline) =>
        program.Find(data, hits, deadline);
}

/// <summary>
/// Regular expressions, run with the .NET non-backtracking engine over the byte view (or
/// the wide views). YARA reports a match at every offset where one starts (they may
/// overlap), so the search restarts one byte after each match start, and every call is
/// limited to a bounded window so that restarting never rescans long matches.
/// </summary>
internal sealed class RegexString(string identifier, bool isPrivate, IReadOnlyList<(YaraRegex.Compiled Regex, bool Wide)> variants, bool fullword)
    : YaraString(identifier, isPrivate)
{
    public override SearchOutcome Find(ReadOnlySpan<byte> data, ByteViewCache view, List<YaraHit> hits, long deadline)
    {
        var results = new List<YaraHit>[variants.Count];
        var timedOut = false;
        for (var v = 0; v < variants.Count; v++)
        {
            results[v] = [];
            var (compiled, wide) = variants[v];
            if (compiled.Required is not null)
            {
                var r = compiled.Required.FindNext(data, 0, deadline);
                if (r == -1) continue;
                if (r == -2) { timedOut = true; continue; }
            }
            // Wide text can start at either byte alignment; each has its own view.
            for (var alignment = 0; alignment < (wide ? 2 : 1) && !timedOut; alignment++)
            {
                var text = wide ? view.GetWide(data, alignment) : view.Get(data);
                var found = compiled.Anchored
                    ? FindAnchored(compiled.Regex, text, results[v].Count, deadline, out var late)
                    : FindWindowed(compiled.Regex, text, wide ? YaraLimits.MaxRegexMatchBytes / 2 : YaraLimits.MaxRegexMatchBytes, results[v].Count, deadline, out late);
                timedOut |= late;
                foreach (var (index, length) in found)
                {
                    var offset = wide ? 2 * index - alignment : index;
                    var bytes = wide ? 2 * length : length;
                    if (!fullword || IsFullword(data, offset, bytes, wide)) results[v].Add(new YaraHit(offset, bytes));
                }
            }
            if (wide) results[v].Sort((a, b) => a.Offset.CompareTo(b.Offset));
        }
        var outcome = MergeVariants(results.Length, (i, list) =>
        {
            list.AddRange(results[i]);
            return SearchOutcome.Complete;
        }, hits);
        return timedOut ? SearchOutcome.TimedOut : outcome;
    }

    /// <summary>Chars searched per call when looking for the next match start.</summary>
    private const int Chunk = 16 * 1024;

    /// <summary>
    /// Finds match starts left to right without ever running the regex over more than one
    /// chunk plus the match limit, so dense or long matches (/a+/ over megabytes of 'a')
    /// stay linear. Each start is then matched in its own window of the match limit, which is
    /// how YARA bounds regex matches. One char before each window gives \b its context.
    /// </summary>
    private static List<(int Index, int Length)> FindWindowed(Regex regex, string text, int limit, int already, long deadline, out bool timedOut)
    {
        timedOut = false;
        var found = new List<(int, int)>();
        var pos = 0;
        while (pos <= text.Length && already + found.Count < YaraLimits.MaxHitsPerString)
        {
            if (YaraClock.Now > deadline) { timedOut = true; break; }
            var start = FirstStart(regex, text, pos, (int)Math.Min(text.Length, (long)pos + Chunk + limit));
            if (start < 0 || start >= pos + Chunk)
            {
                if ((long)pos + Chunk + limit >= text.Length) break;
                pos += Chunk;
                continue;
            }
            var length = MatchAt(regex, text, start, (int)Math.Min(text.Length, (long)start + limit));
            if (length >= 0) found.Add((start, length));
            pos = start + 1;
        }
        return found;
    }

    /// <summary>The leftmost match start in [from, end), or -1.</summary>
    private static int FirstStart(Regex regex, string text, int from, int end)
    {
        var context = from > 0 ? 1 : 0;
        foreach (var m in regex.EnumerateMatches(text.AsSpan(from - context, end - from + context), context))
            return from - context + m.Index;
        return -1;
    }

    /// <summary>The length of the match starting exactly at <paramref name="start"/> within [start, end), or -1.</summary>
    private static int MatchAt(Regex regex, string text, int start, int end)
    {
        var context = start > 0 ? 1 : 0;
        foreach (var m in regex.EnumerateMatches(text.AsSpan(start - context, end - start + context), context))
            return m.Index == context ? m.Length : -1;
        return -1;
    }

    /// <summary>Regexes using ^ or $ run over the whole view, since those anchors refer to its ends.</summary>
    private static List<(int Index, int Length)> FindAnchored(Regex regex, string text, int already, long deadline, out bool timedOut)
    {
        timedOut = false;
        var found = new List<(int, int)>();
        var pos = 0;
        while (pos <= text.Length && already + found.Count < YaraLimits.MaxHitsPerString)
        {
            if (YaraClock.Now > deadline) { timedOut = true; break; }
            var m = regex.Match(text, pos);
            if (!m.Success) break;
            found.Add((m.Index, m.Length));
            pos = m.Index + 1;
        }
        return found;
    }
}

/// <summary>The modifiers written after a string definition.</summary>
internal sealed class StringModifiers
{
    public HashSet<string> Flags { get; } = new(StringComparer.Ordinal);
    public int XorMin { get; set; }
    public int XorMax { get; set; } = 255;
    public byte[]? Base64Alphabet { get; set; }

    public bool Has(string flag) => Flags.Contains(flag);
}

/// <summary>Builds a <see cref="YaraString"/> from its definition, rejecting every combination YARA rejects or Blazma cannot do exactly.</summary>
internal static class YaraStringFactory
{
    private const string StandardAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    public static YaraString Create(string id, Token value, StringModifiers mods)
    {
        var isPrivate = mods.Has("private");
        switch (value.Kind)
        {
            case TokenKind.Hex:
                foreach (var f in mods.Flags)
                    if (f != "private") throw new FormatException($"the '{f}' modifier cannot be used with hex strings");
                return HexProgram.Parse(value.Text) switch
                {
                    BytePattern p => new PatternString(id, isPrivate, [(p, false)], fullword: false),
                    HexProgram program => new HexString(id, isPrivate, program),
                    _ => throw new InvalidOperationException(),
                };

            case TokenKind.Regex:
                foreach (var f in mods.Flags)
                    if (f is "xor" or "base64" or "base64wide") throw new FormatException($"the '{f}' modifier cannot be used with regular expressions");
                {
                    var nocase = mods.Has("nocase") || value.Flags.Contains('i', StringComparison.Ordinal);
                    var dotAll = value.Flags.Contains('s', StringComparison.Ordinal);
                    var variants = new List<(YaraRegex.Compiled, bool)>();
                    if (mods.Has("ascii") || !mods.Has("wide")) variants.Add((YaraRegex.Compile(value.Text, nocase, dotAll, wide: false), false));
                    // The same pattern runs over the wide views; only its prefilter literal is widened.
                    if (mods.Has("wide")) variants.Add((YaraRegex.Compile(value.Text, nocase, dotAll, wide: true), true));
                    return new RegexString(id, isPrivate, variants, mods.Has("fullword"));
                }

            default:
                return CreateText(id, value, mods, isPrivate);
        }
    }

    private static YaraString CreateText(string id, Token value, StringModifiers mods, bool isPrivate)
    {
        var bytes = YaraEscapes.ToBytes(value.Text, out var error);
        if (error is not null) throw new FormatException(error);
        if (bytes.Length == 0) throw new FormatException("empty text string");

        var xor = mods.Has("xor");
        var b64 = mods.Has("base64") || mods.Has("base64wide");
        if (xor && mods.Has("nocase")) throw new FormatException("'xor' and 'nocase' cannot be combined");
        if (xor && mods.Has("fullword")) throw new FormatException("'xor' with 'fullword' is not supported");
        if (b64 && (xor || mods.Has("nocase") || mods.Has("fullword")))
            throw new FormatException("'base64' cannot be combined with 'xor', 'nocase' or 'fullword'");
        if (b64 && (mods.Has("ascii") || mods.Has("wide")))
            throw new FormatException("combining 'base64'/'base64wide' with 'ascii'/'wide' is not supported");

        if (b64)
        {
            if (bytes.Length < 3) throw new FormatException("base64 strings must be at least 3 bytes long");
            var variants = new List<(BytePattern, bool)>();
            foreach (var encoded in Base64Forms(bytes, mods.Base64Alphabet))
            {
                if (mods.Has("base64")) variants.Add((BytePattern.Exact(encoded), false));
                if (mods.Has("base64wide")) variants.Add((BytePattern.Exact(YaraString.Widen(encoded)), true));
            }
            return new PatternString(id, isPrivate, variants, fullword: false);
        }

        var ascii = mods.Has("ascii") || !mods.Has("wide");
        var wide = mods.Has("wide");
        if (xor)
        {
            var plains = new List<byte[]>();
            if (ascii) plains.Add(bytes);
            if (wide) plains.Add(YaraString.Widen(bytes));
            return new XorString(id, isPrivate, plains, mods.XorMin, mods.XorMax);
        }

        var nocase = mods.Has("nocase");
        var list = new List<(BytePattern, bool)>();
        if (ascii) list.Add((nocase ? BytePattern.NoCase(bytes) : BytePattern.Exact(bytes), false));
        if (wide)
        {
            var w = YaraString.Widen(bytes);
            list.Add((nocase ? BytePattern.NoCase(w) : BytePattern.Exact(w), true));
        }
        return new PatternString(id, isPrivate, list, mods.Has("fullword"));
    }

    /// <summary>
    /// The three ways a string can appear inside base64 text, one per starting offset modulo 3.
    /// Only characters whose six bits all come from the string are kept, so each form matches
    /// whatever surrounds the string in the encoded data (YARA's own definition).
    /// </summary>
    public static IEnumerable<byte[]> Base64Forms(byte[] bytes, byte[]? alphabet)
    {
        for (var shift = 0; shift < 3; shift++)
        {
            var padded = new byte[shift + bytes.Length];
            bytes.CopyTo(padded, shift);
            var encoded = Convert.ToBase64String(padded);
            var first = (8 * shift + 5) / 6;
            var end = 8 * (shift + bytes.Length) / 6;
            var chars = encoded[first..end];
            var result = new byte[chars.Length];
            for (var i = 0; i < chars.Length; i++)
                result[i] = alphabet is null ? (byte)chars[i] : alphabet[StandardAlphabet.IndexOf(chars[i], StringComparison.Ordinal)];
            yield return result;
        }
    }

    public static byte[] ParseAlphabet(string raw)
    {
        var alphabet = YaraEscapes.ToBytes(raw, out var error);
        if (error is not null) throw new FormatException(error);
        if (alphabet.Length != 64) throw new FormatException("a base64 alphabet must be exactly 64 bytes long");
        if (alphabet.Distinct().Count() != 64) throw new FormatException("a base64 alphabet must not repeat characters");
        return alphabet;
    }

    internal static string Describe(byte[] bytes) => Encoding.Latin1.GetString(bytes);
}
