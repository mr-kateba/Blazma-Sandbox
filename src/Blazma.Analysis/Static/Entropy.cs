namespace Blazma.Analysis.Static;

public static class Entropy
{
    /// <summary>Shannon entropy in bits per byte (0-8). Above ~7.2 usually means compressed or encrypted data.</summary>
    public static double Of(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (var b in data) counts[b]++;
        double entropy = 0;
        double len = data.Length;
        foreach (var c in counts)
        {
            if (c == 0) continue;
            var p = c / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    public const double PackedThreshold = 7.2;
}
