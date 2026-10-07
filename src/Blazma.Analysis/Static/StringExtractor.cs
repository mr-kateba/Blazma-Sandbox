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

    public static IReadOnlyList<InterestingString> Extract(ReadOnlySpan<byte> data)
    {
        var scan = data.Length > MaxScanBytes ? data[..MaxScanBytes] : data;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var results = new List<InterestingString>();

        foreach (var s in AsciiRuns(scan).Concat(Utf16Runs(scan)))
        {
            if (results.Count >= MaxResults) break;
            Classify(s, seen, results);
        }
        return results;
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

    private static IEnumerable<string> AsciiRuns(ReadOnlySpan<byte> data)
    {
        var list = new List<string>();
        var start = -1;
        for (var i = 0; i <= data.Length; i++)
        {
            var printable = i < data.Length && data[i] >= 0x20 && data[i] < 0x7F;
            if (printable) { if (start < 0) start = i; continue; }
            if (start >= 0 && i - start >= MinLength)
                list.Add(Encoding.ASCII.GetString(data.Slice(start, Math.Min(i - start, MaxLength * 2))));
            start = -1;
        }
        return list;
    }

    /// <summary>UTF-16LE runs at both byte alignments, since strings are not always 2-byte aligned in a file.</summary>
    private static IEnumerable<string> Utf16Runs(ReadOnlySpan<byte> data)
    {
        var list = new List<string>();
        var sb = new StringBuilder();
        for (var start = 0; start < 2; start++)
        {
            for (var i = start; i + 1 < data.Length; i += 2)
            {
                var c = (char)(data[i] | (data[i + 1] << 8));
                if (c >= 0x20 && c < 0x7F && sb.Length < MaxLength * 2) { sb.Append(c); continue; }
                if (sb.Length >= MinLength) list.Add(sb.ToString());
                sb.Clear();
            }
            if (sb.Length >= MinLength) list.Add(sb.ToString());
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
