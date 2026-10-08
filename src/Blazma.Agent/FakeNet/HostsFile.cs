using System.Text;
using System.Text.RegularExpressions;

namespace Blazma.Agent.FakeNet;

/// <summary>
/// The simulated internet's name resolution: every name a program looks up is added to the
/// sandbox's hosts file pointing at 127.0.0.1, where the fake servers listen. The sandbox
/// still has no network adapter, so nothing can leave it.
/// </summary>
internal static partial class HostsFile
{
    public const string Marker = "# blazma-simulated";
    public const int MaxEntries = 500;

    public static bool IsValidHostName(string name) =>
        name.Length is > 0 and <= 253 && HostRegex().IsMatch(name) && !name.Equals("localhost", StringComparison.OrdinalIgnoreCase)
        && !name.EndsWith(".local", StringComparison.OrdinalIgnoreCase) && !name.Contains("..", StringComparison.Ordinal);

    /// <summary>Lines to append for names not already present. Pure, so the rules can be tested anywhere.</summary>
    public static IReadOnlyList<string> NewLines(string existing, IEnumerable<string> names)
    {
        var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var count = 0;
        foreach (var line in existing.Split('\n'))
        {
            var parts = line.Split((char[])[' ', '\t', '\r'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 && !parts[0].StartsWith('#')) foreach (var p in parts.Skip(1).TakeWhile(p => !p.StartsWith('#'))) present.Add(p);
            if (line.Contains(Marker, StringComparison.Ordinal)) count++;
        }
        var lines = new List<string>();
        foreach (var raw in names)
        {
            var name = raw.Trim().TrimEnd('.').ToLowerInvariant();
            if (count + lines.Count >= MaxEntries) break;
            if (!IsValidHostName(name) || !present.Add(name)) continue;
            lines.Add($"127.0.0.1 {name} {Marker}");
        }
        return lines;
    }

    public static string DefaultPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    /// <summary>Appends names to the hosts file. Returns how many were added.</summary>
    public static int Add(string path, IEnumerable<string> names)
    {
        var existing = File.Exists(path) ? File.ReadAllText(path) : string.Empty;
        var lines = NewLines(existing, names);
        if (lines.Count == 0) return 0;
        var prefix = existing.Length == 0 || existing.EndsWith('\n') ? string.Empty : "\r\n";
        File.AppendAllText(path, prefix + string.Join("\r\n", lines) + "\r\n", Encoding.ASCII);
        return lines.Count;
    }

    [GeneratedRegex(@"^(?=.{1,253}$)([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)*[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$", RegexOptions.CultureInvariant)]
    private static partial Regex HostRegex();
}
