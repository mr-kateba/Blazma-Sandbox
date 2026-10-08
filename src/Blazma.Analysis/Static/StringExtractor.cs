using System.Text;
using System.Text.RegularExpressions;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Static;

/// <summary>
/// Extracts a small, classified set of strings. Blazma deliberately does not dump every
/// string: only the kinds that help explain behaviour (URLs, IPs, registry paths, file
/// paths, command lines), capped in count and length.
/// </summary>
public static partial class StringExtractor
{
    public const int MaxResults = 200;
    private const int MinLength = 6;
    private const int MaxLength = 400;
    private const int MaxScanBytes = 32 * 1024 * 1024;
    private const int RunPiece = 4096;
    private const int SplitOverlap = 256;

    public static IReadOnlyList<InterestingString> Extract(ReadOnlySpan<byte> data)
    {
        var scan = data.Length > MaxScanBytes ? data[..MaxScanBytes] : data;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var results = new List<InterestingString>();

        foreach (var s in AsciiRuns(scan, MinLength).Concat(Utf16Runs(scan, MinLength)))
        {
            if (results.Count >= MaxResults) break;
            Classify(s, seen, results);
        }
        return results;
    }

    /// <summary>
    /// Every printable ASCII and UTF-16LE run of at least <paramref name="minLength"/> characters,
    /// for detectors that need more than the classified subset (capabilities, artifacts). Bounded
    /// like <see cref="Extract"/> to the first 32 MB; long runs (script lines) come in overlapping 4 KB pieces.
    /// </summary>
    public static IReadOnlyList<string> Runs(ReadOnlySpan<byte> data, int minLength = 4)
    {
        var scan = data.Length > MaxScanBytes ? data[..MaxScanBytes] : data;
        var list = AsciiRuns(scan, minLength, RunPiece);
        list.AddRange(Utf16Runs(scan, minLength, RunPiece));
        return list;
    }

    private static void Classify(string s, HashSet<string> seen, List<InterestingString> results)
    {
        void Add(InterestingStringKind kind, string value)
        {
            value = value.Trim();
            if (value.Length >= MinLength && results.Count < MaxResults && seen.Add(value))
                results.Add(new InterestingString(kind, value.Length > MaxLength ? value[..MaxLength] : value));
        }

        foreach (Match m in UrlRegex().Matches(s)) Add(InterestingStringKind.Url, m.Value);
        foreach (Match m in IpRegex().Matches(s))
            if (m.Value.Split('.').All(p => int.TryParse(p, out var n) && n <= 255) && !m.Value.StartsWith("0.", StringComparison.Ordinal))
                Add(InterestingStringKind.IpAddress, m.Value);
        foreach (Match m in RegistryRegex().Matches(s)) Add(InterestingStringKind.RegistryPath, m.Value);
        foreach (Match m in CommandRegex().Matches(s)) Add(InterestingStringKind.Command, s);
        foreach (Match m in FilePathRegex().Matches(s)) Add(InterestingStringKind.FilePath, m.Value);
    }

    /// <summary>
    /// ASCII runs. Without <paramref name="splitAt"/> a long run is truncated (the classified view
    /// only needs its start); with it, a long run is cut into overlapping pieces so nothing is lost.
    /// </summary>
    private static List<string> AsciiRuns(ReadOnlySpan<byte> data, int minLength, int? splitAt = null)
    {
        var list = new List<string>();
        var start = -1;
        for (var i = 0; i <= data.Length; i++)
        {
            var printable = i < data.Length && data[i] >= 0x20 && data[i] < 0x7F;
            if (printable) { if (start < 0) start = i; continue; }
            if (start >= 0 && i - start >= minLength)
            {
                var run = data[start..i];
                if (splitAt is not { } piece)
                {
                    list.Add(Encoding.ASCII.GetString(run[..Math.Min(run.Length, MaxLength * 2)]));
                }
                else
                {
                    for (var at = 0; at < run.Length; at += piece - SplitOverlap)
                    {
                        list.Add(Encoding.ASCII.GetString(run.Slice(at, Math.Min(piece, run.Length - at))));
                        if (at + piece >= run.Length) break;
                    }
                }
            }
            start = -1;
        }
        return list;
    }

    /// <summary>UTF-16LE runs at both byte alignments, since strings are not always 2-byte aligned in a file.</summary>
    private static List<string> Utf16Runs(ReadOnlySpan<byte> data, int minLength, int? splitAt = null)
    {
        var list = new List<string>();
        var sb = new StringBuilder();
        var max = splitAt ?? MaxLength * 2;
        for (var start = 0; start < 2; start++)
        {
            for (var i = start; i + 1 < data.Length; i += 2)
            {
                var c = (char)(data[i] | (data[i + 1] << 8));
                var printable = c >= 0x20 && c < 0x7F;
                if (printable && sb.Length < max) { sb.Append(c); continue; }
                if (sb.Length >= minLength) list.Add(sb.ToString());
                if (printable && splitAt is not null)
                {
                    // Keep going with an overlap, so a pattern across the cut is still seen.
                    var tail = sb.ToString(sb.Length - SplitOverlap, SplitOverlap);
                    sb.Clear().Append(tail).Append(c);
                    continue;
                }
                sb.Clear();
            }
            if (sb.Length >= minLength) list.Add(sb.ToString());
            sb.Clear();
        }
        return list;
    }

    [GeneratedRegex(@"\bhttps?://[A-Za-z0-9.\-]+(?::\d{1,5})?(?:/[^\s""'<>]*)?", RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.CultureInvariant)]
    private static partial Regex IpRegex();

    [GeneratedRegex(@"\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s""']{4,}|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run[^\s""']*", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex RegistryRegex();

    [GeneratedRegex(@"(?:powershell(?:\.exe)?\s+-|cmd(?:\.exe)?\s+/c|-encodedcommand|frombase64string|invoke-expression|downloadstring|schtasks\s+/create|vssadmin\s+delete)", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex CommandRegex();

    [GeneratedRegex(@"\b[A-Za-z]:\\[^\s""'<>|*?]{3,}|%(?:APPDATA|TEMP|LOCALAPPDATA|PROGRAMDATA|USERPROFILE)%\\[^\s""'<>|*?]+", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex FilePathRegex();
}
