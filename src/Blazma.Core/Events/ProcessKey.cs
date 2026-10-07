using System.Globalization;

namespace Blazma.Core.Events;

/// <summary>
/// Identifies one process instance. Windows reuses PIDs, so a PID alone is not enough to
/// tell two processes apart over a long analysis; the start time (in ticks relative to
/// the analysis start) disambiguates.
/// </summary>
public readonly record struct ProcessKey(int Pid, long StartTicks)
{
    public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"{Pid}@{StartTicks}");

    public static bool TryParse(string? text, out ProcessKey key)
    {
        key = default;
        if (string.IsNullOrEmpty(text)) return false;
        var at = text.IndexOf('@', StringComparison.Ordinal);
        if (at <= 0) return false;
        if (!int.TryParse(text.AsSpan(0, at), NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid)) return false;
        if (!long.TryParse(text.AsSpan(at + 1), NumberStyles.Integer, CultureInfo.InvariantCulture, out var ticks)) return false;
        key = new ProcessKey(pid, ticks);
        return true;
    }
}
