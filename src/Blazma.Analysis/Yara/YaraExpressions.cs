using System.Buffers.Binary;

namespace Blazma.Analysis.Yara;

internal enum YType { Bool, Int, String, Unknown }

/// <summary>
/// A condition value: an integer, a boolean, or undefined (reading past the end of the data,
/// <c>@a[5]</c> when there are two matches, division by zero). Undefined spreads through
/// arithmetic and comparisons and counts as false, as in YARA.
/// </summary>
internal readonly struct YVal
{
    private const byte UndefinedKind = 0, IntKind = 1, BoolKind = 2, StringKind = 3;

    private YVal(long value, byte kind, string? text = null)
    {
        Value = value;
        Kind = kind;
        Text = text;
    }

    public long Value { get; }
    private byte Kind { get; }

    /// <summary>For string values (module fields such as <c>pe.sections[0].name</c>).</summary>
    public string? Text { get; }

    public static YVal Undefined => default;
    public static YVal Int(long v) => new(v, IntKind);
    public static YVal Bool(bool b) => new(b ? 1 : 0, BoolKind);
    public static YVal Str(string? text) => text is null ? Undefined : new(text.Length, StringKind, text);

    public bool IsUndefined => Kind == UndefinedKind;
    public bool IsString => Kind == StringKind;
    public bool IsTrue => Kind == StringKind ? Text!.Length > 0 : Kind != UndefinedKind && Value != 0;
}

/// <summary>Thrown when one rule's condition runs out of evaluation steps.</summary>
internal sealed class YaraBudgetException() : Exception("evaluation step budget exhausted");

/// <summary>
/// Everything one scan needs while evaluating conditions. A ref struct so it can hold the
/// scanned span without copying data that may be hundreds of megabytes.
/// </summary>
internal ref struct YaraScanState
{
    public ReadOnlySpan<byte> Data;
    public ByteViewCache View;
    public YaraString[] Strings;
    public List<YaraHit>?[] Hits;
    public bool[] RuleResults;
    public long[] Vars;
    public List<string> Warnings;
    public long ScanDeadline;
    public bool ScanBudgetReported;
    private PeModuleData? _pe;
    private bool _peLoaded;

    // Per rule being evaluated.
    public int StringBase;
    public int RuleBase;
    public int CurrentString;
    public long Steps;
    public string RuleName;

    /// <summary>The pe module's view of the data, parsed on first use; null when the data is not a PE.</summary>
    public PeModuleData? GetPe()
    {
        if (!_peLoaded)
        {
            _peLoaded = true;
            _pe = PeModuleData.TryBuild(Data);
        }
        return _pe;
    }

    public void Step()
    {
        if (++Steps > YaraLimits.MaxEvaluationSteps) throw new YaraBudgetException();
    }

    /// <summary>The hits of a string of the current rule, searched on first use.</summary>
    public List<YaraHit> HitsOf(int localIndex)
    {
        Step();
        var index = StringBase + (localIndex < 0 ? CurrentString : localIndex);
        if (Hits[index] is { } cached) return cached;

        var list = new List<YaraHit>();
        Hits[index] = list;
        var str = Strings[index];
        if (YaraClock.Now > ScanDeadline)
        {
            if (!ScanBudgetReported)
                Warnings.Add($"The scan time budget ({YaraLimits.ScanBudget.TotalSeconds:0} s) ran out; strings searched after that point count as not found.");
            ScanBudgetReported = true;
            return list;
        }
        var deadline = Math.Min(ScanDeadline, YaraClock.After(YaraLimits.StringSearchBudget));
        var outcome = str.Find(Data, View, list, deadline);
        if (outcome == SearchOutcome.TimedOut)
            Warnings.Add($"Rule {RuleName}: the search for {str.Identifier} stopped after its time budget; its matches may be incomplete.");
        return list;
    }
}

internal abstract class YExpr(YType type, params YExpr?[] children)
{
    public YType Type { get; } = type;

    /// <summary>Height of the tree below this node; bounds evaluation recursion.</summary>
    public int Depth { get; } = 1 + children.Where(c => c is not null).Select(c => c!.Depth).DefaultIfEmpty(0).Max();

    public abstract YVal Eval(ref YaraScanState s);
}

/// <summary>Stands in for anything the rule was rejected for; never evaluated.</summary>
internal sealed class UnknownExpr() : YExpr(YType.Unknown)
{
    public override YVal Eval(ref YaraScanState s) => YVal.Undefined;
}

internal sealed class ConstExpr(YVal value, YType type) : YExpr(type)
{
    public override YVal Eval(ref YaraScanState s) => value;
}

internal sealed class FilesizeExpr() : YExpr(YType.Int)
{
    public override YVal Eval(ref YaraScanState s) => YVal.Int(s.Data.Length);
}

internal sealed class VarExpr(int slot) : YExpr(YType.Int)
{
    public override YVal Eval(ref YaraScanState s) => YVal.Int(s.Vars[slot]);
}

internal sealed class RuleRefExpr(int localIndex) : YExpr(YType.Bool)
{
    public override YVal Eval(ref YaraScanState s) => YVal.Bool(s.RuleResults[s.RuleBase + localIndex]);
}

internal sealed class UnaryExpr(char op, YExpr operand) : YExpr(YType.Int, operand)
{
    public override YVal Eval(ref YaraScanState s)
    {
        var v = operand.Eval(ref s);
        if (v.IsUndefined) return v;
        return YVal.Int(op == '-' ? unchecked(-v.Value) : ~v.Value);
    }
}

internal sealed class ArithExpr(string op, YExpr left, YExpr right) : YExpr(YType.Int, left, right)
{
    public override YVal Eval(ref YaraScanState s)
    {
        var l = left.Eval(ref s);
        if (l.IsUndefined) return l;
        var r = right.Eval(ref s);
        if (r.IsUndefined) return r;
        long a = l.Value, b = r.Value;
        unchecked
        {
            switch (op)
            {
                case "+": return YVal.Int(a + b);
                case "-": return YVal.Int(a - b);
                case "*": return YVal.Int(a * b);
                case "\\": return b == 0 || (a == long.MinValue && b == -1) ? YVal.Undefined : YVal.Int(a / b);
                case "%": return b == 0 || (a == long.MinValue && b == -1) ? YVal.Undefined : YVal.Int(a % b);
                case "&": return YVal.Int(a & b);
                case "|": return YVal.Int(a | b);
                case "^": return YVal.Int(a ^ b);
                case "<<": return b < 0 ? YVal.Undefined : YVal.Int(b >= 64 ? 0 : a << (int)b);
                case ">>": return b < 0 ? YVal.Undefined : YVal.Int(b >= 64 ? 0 : a >> (int)b);
                default: return YVal.Undefined;
            }
        }
    }
}

internal sealed class CompareExpr(string op, YExpr left, YExpr right) : YExpr(YType.Bool, left, right)
{
    public override YVal Eval(ref YaraScanState s)
    {
        var l = left.Eval(ref s);
        if (l.IsUndefined) return l;
        var r = right.Eval(ref s);
        if (r.IsUndefined) return r;
        if (l.IsString || r.IsString)
        {
            // Strings compare byte for byte (ordinal), as in YARA; the parser allows only == and !=.
            var equal = l.IsString && r.IsString && string.Equals(l.Text, r.Text, StringComparison.Ordinal);
            return YVal.Bool(op == "==" ? equal : !equal);
        }
        // Booleans compare by truth, integers by value.
        long a = left.Type == YType.Bool ? (l.IsTrue ? 1 : 0) : l.Value;
        long b = right.Type == YType.Bool ? (r.IsTrue ? 1 : 0) : r.Value;
        return YVal.Bool(op switch
        {
            "==" => a == b,
            "!=" => a != b,
            "<" => a < b,
            "<=" => a <= b,
            ">" => a > b,
            _ => a >= b,
        });
    }
}

/// <summary>contains, startswith, endswith, iequals and their case-insensitive forms (ASCII case only, as in YARA).</summary>
internal sealed class StringOpExpr(string op, YExpr left, YExpr right) : YExpr(YType.Bool, left, right)
{
    public override YVal Eval(ref YaraScanState s)
    {
        var l = left.Eval(ref s);
        if (!l.IsString) return YVal.Undefined;
        var r = right.Eval(ref s);
        if (!r.IsString) return YVal.Undefined;
        string a = l.Text!, b = r.Text!;
        var ignoreCase = op.StartsWith('i');
        if (ignoreCase) { a = AsciiLower(a); b = AsciiLower(b); }
        return YVal.Bool(op.TrimStart('i') switch
        {
            "contains" => a.Contains(b, StringComparison.Ordinal),
            "startswith" => a.StartsWith(b, StringComparison.Ordinal),
            "endswith" => a.EndsWith(b, StringComparison.Ordinal),
            _ => string.Equals(a, b, StringComparison.Ordinal),
        });
    }

    private static string AsciiLower(string text) =>
        string.Create(text.Length, text, (span, t) => { for (var i = 0; i < t.Length; i++) span[i] = t[i] is >= 'A' and <= 'Z' ? (char)(t[i] + 32) : t[i]; });
}

internal sealed class AndExpr(List<YExpr> items) : YExpr(YType.Bool, [.. items])
{
    public override YVal Eval(ref YaraScanState s)
    {
        foreach (var item in items)
            if (!item.Eval(ref s).IsTrue) return YVal.Bool(false);
        return YVal.Bool(true);
    }
}

internal sealed class OrExpr(List<YExpr> items) : YExpr(YType.Bool, [.. items])
{
    public override YVal Eval(ref YaraScanState s)
    {
        foreach (var item in items)
            if (item.Eval(ref s).IsTrue) return YVal.Bool(true);
        return YVal.Bool(false);
    }
}

internal sealed class NotExpr(YExpr operand) : YExpr(YType.Bool, operand)
{
    public override YVal Eval(ref YaraScanState s)
    {
        var v = operand.Eval(ref s);
        return v.IsUndefined ? v : YVal.Bool(!v.IsTrue);
    }
}

internal sealed class DefinedExpr(YExpr operand) : YExpr(YType.Bool, operand)
{
    public override YVal Eval(ref YaraScanState s) => YVal.Bool(!operand.Eval(ref s).IsUndefined);
}

/// <summary><c>$a</c>, <c>$a at x</c>, <c>$a in (lo..hi)</c>. Index -1 is the anonymous <c>$</c> of a for-of loop.</summary>
internal sealed class StringMatchExpr(int index, YExpr? at, YExpr? lo, YExpr? hi) : YExpr(YType.Bool, at, lo, hi)
{
    public override YVal Eval(ref YaraScanState s)
    {
        var hits = s.HitsOf(index);
        if (at is not null)
        {
            var x = at.Eval(ref s);
            if (x.IsUndefined) return x;
            return YVal.Bool(hits.Exists(h => h.Offset == x.Value));
        }
        if (lo is not null)
        {
            var a = lo.Eval(ref s);
            var b = hi!.Eval(ref s);
            if (a.IsUndefined || b.IsUndefined) return YVal.Undefined;
            return YVal.Bool(hits.Exists(h => h.Offset >= a.Value && h.Offset <= b.Value));
        }
        return YVal.Bool(hits.Count > 0);
    }
}

/// <summary><c>#a</c> and <c>#a in (lo..hi)</c>; saturates at <see cref="YaraLimits.MaxHitsPerString"/>.</summary>
internal sealed class StringCountExpr(int index, YExpr? lo, YExpr? hi) : YExpr(YType.Int, lo, hi)
{
    public override YVal Eval(ref YaraScanState s)
    {
        var hits = s.HitsOf(index);
        if (lo is null) return YVal.Int(hits.Count);
        var a = lo.Eval(ref s);
        var b = hi!.Eval(ref s);
        if (a.IsUndefined || b.IsUndefined) return YVal.Undefined;
        return YVal.Int(hits.Count(h => h.Offset >= a.Value && h.Offset <= b.Value));
    }
}

/// <summary><c>@a[i]</c> (offset) or <c>!a[i]</c> (length), 1-based; undefined outside 1..#a.</summary>
internal sealed class StringOccurrenceExpr(int index, YExpr which, bool length) : YExpr(YType.Int, which)
{
    public override YVal Eval(ref YaraScanState s)
    {
        var i = which.Eval(ref s);
        if (i.IsUndefined) return i;
        var hits = s.HitsOf(index);
        if (i.Value < 1 || i.Value > hits.Count) return YVal.Undefined;
        var hit = hits[(int)i.Value - 1];
        return YVal.Int(length ? hit.Length : hit.Offset);
    }
}

/// <summary>uint8/16/32 and int8/16/32, little or big endian; undefined outside the data.</summary>
internal sealed class ReadIntExpr(int size, bool signed, bool bigEndian, YExpr offset) : YExpr(YType.Int, offset)
{
    public override YVal Eval(ref YaraScanState s)
    {
        var o = offset.Eval(ref s);
        if (o.IsUndefined || o.Value < 0 || o.Value > s.Data.Length - size) return YVal.Undefined;
        var span = s.Data.Slice((int)o.Value, size);
        long v = size switch
        {
            1 => signed ? (sbyte)span[0] : span[0],
            2 => bigEndian
                ? (signed ? BinaryPrimitives.ReadInt16BigEndian(span) : BinaryPrimitives.ReadUInt16BigEndian(span))
                : (signed ? BinaryPrimitives.ReadInt16LittleEndian(span) : BinaryPrimitives.ReadUInt16LittleEndian(span)),
            _ => bigEndian
                ? (signed ? BinaryPrimitives.ReadInt32BigEndian(span) : BinaryPrimitives.ReadUInt32BigEndian(span))
                : (signed ? BinaryPrimitives.ReadInt32LittleEndian(span) : BinaryPrimitives.ReadUInt32LittleEndian(span)),
        };
        return YVal.Int(v);
    }
}

internal enum QuantKind { Any, All, None, Count, Percent }

/// <summary>any / all / none / N / N% — how many of a set (or loop iterations) must be true.</summary>
internal sealed class Quantifier(QuantKind kind, YExpr? count = null, long percent = 0)
{
    public QuantKind Kind { get; } = kind;
    public YExpr? CountExpr { get; } = count;

    /// <summary>Resolves N once per evaluation; null means undefined.</summary>
    public long? Required(ref YaraScanState s, int total)
    {
        switch (Kind)
        {
            case QuantKind.Any: return 1;
            case QuantKind.All: return total;
            case QuantKind.None: return 0;
            case QuantKind.Percent: return (percent * total + 99) / 100;
            default:
                var n = CountExpr!.Eval(ref s);
                return n.IsUndefined ? null : n.Value;
        }
    }

    /// <summary>"none" and "0 of" mean exactly zero; everything else means at least N.</summary>
    public static bool Satisfied(long required, int trueCount, bool exactlyZero) =>
        exactlyZero ? trueCount == 0 : trueCount >= required;

    public bool ExactlyZero(long required) => Kind == QuantKind.None || (Kind == QuantKind.Count && required == 0);
}

/// <summary><c>N of ($a, $b*)</c>, <c>N of them</c>, <c>N of (rule*)</c>, optionally with <c>at</c> / <c>in</c>.</summary>
internal sealed class OfExpr(Quantifier quant, int[] items, bool rules, YExpr? at, YExpr? lo, YExpr? hi)
    : YExpr(YType.Bool, quant.CountExpr, at, lo, hi)
{
    public override YVal Eval(ref YaraScanState s)
    {
        var required = quant.Required(ref s, items.Length);
        if (required is null) return YVal.Undefined;
        long? x = null, a = null, b = null;
        if (at is not null)
        {
            var v = at.Eval(ref s);
            if (v.IsUndefined) return v;
            x = v.Value;
        }
        if (lo is not null)
        {
            var va = lo.Eval(ref s);
            var vb = hi!.Eval(ref s);
            if (va.IsUndefined || vb.IsUndefined) return YVal.Undefined;
            (a, b) = (va.Value, vb.Value);
        }

        var exactlyZero = quant.ExactlyZero(required.Value);
        var count = 0;
        foreach (var item in items)
        {
            bool ok;
            if (rules) ok = s.RuleResults[s.RuleBase + item];
            else
            {
                var hits = s.HitsOf(item);
                ok = x is { } at0 ? hits.Exists(h => h.Offset == at0)
                    : a is { } from ? hits.Exists(h => h.Offset >= from && h.Offset <= b!.Value)
                    : hits.Count > 0;
            }
            if (ok) count++;
            if (!exactlyZero && count >= required.Value) return YVal.Bool(true);
            if (exactlyZero && count > 0) return YVal.Bool(false);
        }
        return YVal.Bool(Quantifier.Satisfied(required.Value, count, exactlyZero));
    }
}

/// <summary><c>for N of (set) : (body)</c>, where the body uses <c>$ # @ !</c> for the current string.</summary>
internal sealed class ForOfExpr(Quantifier quant, int[] strings, YExpr body) : YExpr(YType.Bool, quant.CountExpr, body)
{
    public override YVal Eval(ref YaraScanState s)
    {
        var required = quant.Required(ref s, strings.Length);
        if (required is null) return YVal.Undefined;
        var exactlyZero = quant.ExactlyZero(required.Value);
        var saved = s.CurrentString;
        var count = 0;
        try
        {
            foreach (var index in strings)
            {
                s.Step();
                s.CurrentString = index;
                if (body.Eval(ref s).IsTrue) count++;
                if (!exactlyZero && count >= required.Value) return YVal.Bool(true);
                if (exactlyZero && count > 0) return YVal.Bool(false);
            }
        }
        finally
        {
            s.CurrentString = saved;
        }
        return YVal.Bool(Quantifier.Satisfied(required.Value, count, exactlyZero));
    }
}

/// <summary><c>for N i in (lo..hi) : (body)</c> or <c>for N i in (a, b, c) : (body)</c>.</summary>
internal sealed class ForInExpr(Quantifier quant, int slot, YExpr? lo, YExpr? hi, List<YExpr>? values, YExpr body)
    : YExpr(YType.Bool, [quant.CountExpr, lo, hi, body, .. (values ?? new List<YExpr>())])
{
    public override YVal Eval(ref YaraScanState s)
    {
        long first, total;
        if (values is null)
        {
            var a = lo!.Eval(ref s);
            var b = hi!.Eval(ref s);
            if (a.IsUndefined || b.IsUndefined) return YVal.Undefined;
            first = a.Value;
            total = b.Value < a.Value ? 0 : (long)Math.Min((ulong)(b.Value - a.Value) + 1, (ulong)long.MaxValue);
            if (total > YaraLimits.MaxLoopIterations)
            {
                s.Warnings.Add($"Rule {s.RuleName}: a for loop over {total} values exceeds the limit of {YaraLimits.MaxLoopIterations}; the loop counts as undefined.");
                return YVal.Undefined;
            }
        }
        else
        {
            first = 0;
            total = values.Count;
        }

        var required = quant.Required(ref s, (int)total);
        if (required is null) return YVal.Undefined;
        var exactlyZero = quant.ExactlyZero(required.Value);
        var count = 0;
        for (long k = 0; k < total; k++)
        {
            s.Step();
            if (values is null) s.Vars[slot] = first + k;
            else
            {
                var v = values[(int)k].Eval(ref s);
                if (v.IsUndefined) continue;
                s.Vars[slot] = v.Value;
            }
            if (body.Eval(ref s).IsTrue) count++;
            if (!exactlyZero && count >= required.Value) return YVal.Bool(true);
            if (exactlyZero && count > 0) return YVal.Bool(false);
        }
        return YVal.Bool(Quantifier.Satisfied(required.Value, count, exactlyZero));
    }
}
