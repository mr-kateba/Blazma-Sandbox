using System.Text.RegularExpressions;

namespace Blazma.Reporting;

/// <summary>
/// Removes personal details before a report leaves Blazma: the user name, the machine
/// name and the profile folder. Applied to every string in exported reports when the
/// privacy setting is on (the default).
/// </summary>
public sealed partial class Redactor
{
    private readonly List<(Regex Pattern, string Replacement)> _rules = [];

    public Redactor(IEnumerable<string>? userNames = null, IEnumerable<string>? machineNames = null)
    {
        _rules.Add((UsersFolderRegex(), @"$1<user>"));
        foreach (var name in (userNames ?? [Environment.UserName]).Where(n => n.Length >= 3).Distinct(StringComparer.OrdinalIgnoreCase))
            _rules.Add((new Regex(@"(?<![A-Za-z0-9])" + Regex.Escape(name) + @"(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), "<user>"));
        foreach (var name in (machineNames ?? [Environment.MachineName]).Where(n => n.Length >= 3).Distinct(StringComparer.OrdinalIgnoreCase))
            _rules.Add((new Regex(@"(?<![A-Za-z0-9])" + Regex.Escape(name) + @"(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), "<machine>"));
        _rules.Add((UserSidRegex(), "S-1-5-21-<sid>"));
    }

    public static Redactor None { get; } = new([], []) { Disabled = true };

    public bool Disabled { get; private init; }

    public string? Apply(string? text)
    {
        if (Disabled || string.IsNullOrEmpty(text)) return text;
        foreach (var (pattern, replacement) in _rules) text = pattern.Replace(text, replacement);
        return text;
    }

    [GeneratedRegex(@"([A-Za-z]:\\Users\\)[^\\""\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UsersFolderRegex();

    [GeneratedRegex(@"S-1-5-21-\d+-\d+-\d+(-\d+)?", RegexOptions.CultureInvariant)]
    private static partial Regex UserSidRegex();
}
