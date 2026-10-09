using System.Buffers;
using System.Numerics;

namespace Blazma.Analysis.Yara;

/// <summary>
/// A fixed-length pattern where each byte is compared under a mask, optionally negated. One
/// shape covers text strings (nocase is mask 0xDF on letters), wide strings, hex bytes and
/// nibble wildcards. Candidates are found with a vectorised <c>IndexOf</c> on the most
/// selective part (the "atom") and then verified, so data is never walked byte by byte.
/// </summary>
internal sealed class BytePattern
{
    private readonly byte[] _values;
    private readonly byte[] _masks;
    private readonly bool[]? _negated;
    private readonly bool _exact;

    private readonly int _anchorOffset;
    private readonly byte[]? _anchorRun;
    private readonly SearchValues<byte>? _anchorSet;

    private BytePattern(byte[] values, byte[] masks, bool[]? negated)
    {
        _values = values;
        _masks = masks;
        _negated = negated is not null && Array.IndexOf(negated, true) >= 0 ? negated : null;
        _exact = _negated is null && Array.TrueForAll(masks, m => m == 0xFF);
        for (var i = 0; i < values.Length; i++) _values[i] &= _masks[i];
        (_anchorOffset, _anchorRun, _anchorSet) = ChooseAnchor();
    }

    public int Length => _values.Length;

    public static BytePattern Exact(ReadOnlySpan<byte> bytes)
    {
        var masks = new byte[bytes.Length];
        Array.Fill(masks, (byte)0xFF);
        return new BytePattern(bytes.ToArray(), masks, null);
    }

    public static BytePattern Masked(byte[] values, byte[] masks, bool[]? negated = null) => new(values, masks, negated);

    /// <summary>Case-insensitive ASCII letters, the way YARA's nocase works (no other folding).</summary>
    public static BytePattern NoCase(ReadOnlySpan<byte> bytes)
    {
        var values = bytes.ToArray();
        var masks = new byte[values.Length];
        for (var i = 0; i < values.Length; i++) masks[i] = IsAsciiLetter(values[i]) ? (byte)0xDF : (byte)0xFF;
        return new BytePattern(values, masks, null);
    }

    public static bool IsAsciiLetter(byte b) => (uint)((b | 0x20) - 'a') <= 'z' - 'a';

    public bool MatchesAt(ReadOnlySpan<byte> data, int pos)
    {
        if (pos < 0 || pos > data.Length - _values.Length) return false;
        var window = data.Slice(pos, _values.Length);
        if (_exact) return window.SequenceEqual(_values);
        for (var i = 0; i < window.Length; i++)
        {
            var eq = (window[i] & _masks[i]) == _values[i];
            if (_negated is not null && _negated[i]) eq = !eq;
            if (!eq) return false;
        }
        return true;
    }

    /// <summary>
    /// The first start position at or after <paramref name="from"/> where the whole pattern
    /// matches, -1 if there is none, or -2 if the deadline passed while looking.
    /// </summary>
    public int FindNext(ReadOnlySpan<byte> data, int from, long deadline)
    {
        var pos = Math.Max(from, 0);
        var checks = 0;
        while (pos <= data.Length - _values.Length)
        {
            int idx;
            var window = data[(pos + _anchorOffset)..(data.Length - _values.Length + _anchorOffset + AnchorLength)];
            if (_anchorRun is not null) idx = window.IndexOf(_anchorRun);
            else if (_anchorSet is not null) idx = window.IndexOfAny(_anchorSet);
            else idx = 0;
            if (idx < 0) return -1;

            var candidate = pos + idx;
            if (MatchesAt(data, candidate)) return candidate;
            pos = candidate + 1;
            if (++checks % 4096 == 0 && YaraClock.Now > deadline) return -2;
        }
        return -1;
    }

    private int AnchorLength => _anchorRun?.Length ?? 1;

    /// <summary>
    /// Picks the part of the pattern to search for: the best run of exact bytes, or, when
    /// none is good (nocase letters, wide strings full of zeros), the single position whose
    /// set of allowed values is smallest. Common filler bytes make poor atoms.
    /// </summary>
    private (int Offset, byte[]? Run, SearchValues<byte>? Set) ChooseAnchor()
    {
        double bestRunScore = 0;
        int bestRunStart = -1, bestRunLength = 0;
        for (var i = 0; i < _values.Length;)
        {
            if (!IsExactAt(i)) { i++; continue; }
            var start = i;
            double score = 0;
            while (i < _values.Length && IsExactAt(i)) score += Quality(_values[i++]);
            if (score > bestRunScore || (score == bestRunScore && i - start > bestRunLength))
            {
                bestRunScore = score;
                bestRunStart = start;
                bestRunLength = i - start;
            }
        }

        double bestSetScore = 0;
        var bestSetPos = -1;
        for (var i = 0; i < _values.Length; i++)
        {
            if (IsExactAt(i)) continue;
            var count = AllowedCount(i);
            var score = count switch { 2 => 3.0, <= 16 => 2.0, < 128 => 0.5, _ => 0.0 };
            if (score > bestSetScore) { bestSetScore = score; bestSetPos = i; }
        }

        if (bestRunStart >= 0 && bestRunScore >= bestSetScore)
            return (bestRunStart, _values.AsSpan(bestRunStart, bestRunLength).ToArray(), null);
        if (bestSetPos >= 0)
            return (bestSetPos, null, SearchValues.Create(AllowedValues(bestSetPos)));
        return (0, null, null);
    }

    private bool IsExactAt(int i) => _masks[i] == 0xFF && (_negated is null || !_negated[i]);

    private int AllowedCount(int i)
    {
        var count = 1 << BitOperations.PopCount((uint)(~_masks[i] & 0xFF));
        return _negated is not null && _negated[i] ? 256 - count : count;
    }

    private byte[] AllowedValues(int i)
    {
        var list = new List<byte>();
        for (var b = 0; b < 256; b++)
        {
            var eq = (b & _masks[i]) == _values[i];
            if (_negated is not null && _negated[i]) eq = !eq;
            if (eq) list.Add((byte)b);
        }
        return [.. list];
    }

    /// <summary>The set of values the first byte may take (all 256 when unconstrained).</summary>
    public byte[] FirstByteValues() => _values.Length == 0 ? [] : AllowedValues(0);

    private static double Quality(byte b) => b is 0x00 or 0xFF or 0x20 or 0x0A or 0x0D or 0x90 or 0xCC ? 1 : 4;
}

/// <summary>Monotonic timestamps for the search budgets.</summary>
internal static class YaraClock
{
    public static long Now => System.Diagnostics.Stopwatch.GetTimestamp();

    public static long After(TimeSpan span) => Now + (long)(span.TotalSeconds * System.Diagnostics.Stopwatch.Frequency);
}
