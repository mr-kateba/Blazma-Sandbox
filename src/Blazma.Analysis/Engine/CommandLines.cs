using System.Text;
using System.Text.RegularExpressions;
using Blazma.Analysis.Text;
using Blazma.Core.Processes;

namespace Blazma.Analysis.Engine;

/// <summary>
/// A command the analyzed tree asked Windows to run later or through another process: a
/// scheduled task (schtasks, Register-ScheduledTask), a service (sc create, New-Service) or a
/// WMI process (wmic process call create). Windows then performs the work from its own
/// processes, so this is the evidence that ties that work back to the sample.
/// </summary>
public sealed record LaunchRegistration(PersistenceTechnique? Technique, string? Name, string Command, ProcessNode RegisteredBy);

/// <summary>Parsing and comparison of Windows command lines.</summary>
public static partial class CommandLines
{
    private static readonly (string Variable, string Value)[] Machine =
    [
        ("%systemroot%", @"C:\Windows"), ("%windir%", @"C:\Windows"), ("%programfiles%", @"C:\Program Files"),
        ("%programfiles(x86)%", @"C:\Program Files (x86)"), ("%programw6432%", @"C:\Program Files"), ("%programdata%", @"C:\ProgramData"),
        ("%commonprogramfiles%", @"C:\Program Files\Common Files"), ("%systemdrive%", "C:"),
    ];

    /// <summary>Splits like the Windows C runtime: spaces separate arguments, double quotes group them, \" is a literal quote.</summary>
    public static IReadOnlyList<string> Tokenize(string commandLine)
    {
        var tokens = new List<string>();
        var sb = new StringBuilder();
        var inQuotes = false;
        var any = false;
        for (var i = 0; i < commandLine.Length; i++)
        {
            var c = commandLine[i];
            if (c == '\\' && i + 1 < commandLine.Length && commandLine[i + 1] == '"') { sb.Append('"'); i++; any = true; continue; }
            if (c == '"') { inQuotes = !inQuotes; any = true; continue; }
            if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (any) { tokens.Add(sb.ToString()); sb.Clear(); any = false; }
                continue;
            }
            sb.Append(c);
            any = true;
        }
        if (any) tokens.Add(sb.ToString());
        return tokens;
    }

    /// <summary>Replaces the machine-wide environment variables Windows uses in service and task commands.</summary>
    public static string ExpandMachineVariables(string text)
    {
        if (!text.Contains('%', StringComparison.Ordinal)) return text;
        foreach (var (variable, value) in Machine)
            text = text.Replace(variable, value, StringComparison.OrdinalIgnoreCase);
        return text;
    }

    /// <summary>Lower case, without quotes, NT prefixes or repeated spaces: two spellings of one command compare equal.</summary>
    public static string Normalize(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return string.Empty;
        var text = ExpandMachineVariables(commandLine).Replace(@"\??\", string.Empty, StringComparison.Ordinal).Replace("\"", string.Empty, StringComparison.Ordinal);
        return SpacesRegex().Replace(text, " ").Trim().ToLowerInvariant();
    }

    /// <summary>The program a command starts: the quoted first part, or the text up to the first program extension.</summary>
    public static string ExecutablePath(string commandLine)
    {
        var t = ExpandMachineVariables(commandLine).TrimStart();
        if (t.StartsWith(@"\??\", StringComparison.Ordinal)) t = t[4..];
        if (t.StartsWith('"'))
        {
            var end = t.IndexOf('"', 1);
            return end > 1 ? t[1..end] : t[1..];
        }
        var m = ProgramRegex().Match(t);
        if (m.Success) return m.Groups["path"].Value;
        var space = t.IndexOf(' ', StringComparison.Ordinal);
        return space < 0 ? t : t[..space];
    }

    /// <summary>
    /// Whether a command refers to a file. A full path must match exactly. A bare file name (or one
    /// behind an environment variable) matches only at a path boundary and only for program files
    /// with a distinctive name, so a folder called "update" does not match "MicrosoftEdgeUpdate.exe".
    /// </summary>
    public static bool References(string command, string path)
    {
        if (string.IsNullOrEmpty(command) || string.IsNullOrEmpty(path)) return false;
        if (ContainsPath(command, path) || ContainsPath(ExpandMachineVariables(command), path)) return true;

        var name = PathRules.FileName(path);
        if (name.Length < 5 || !PathRules.IsExecutablePath(name)) return false;
        for (var i = command.IndexOf(name, StringComparison.OrdinalIgnoreCase); i >= 0; i = command.IndexOf(name, i + name.Length, StringComparison.OrdinalIgnoreCase))
        {
            var before = i == 0 ? ' ' : command[i - 1];
            var end = i + name.Length;
            var after = end >= command.Length ? ' ' : command[end];
            if (before is not ('\\' or '/' or '"' or '\'' or ' ' or '=') || after is not (' ' or '"' or '\'' or ',')) continue;

            // The path this name belongs to: an absolute one that is not the dropped file is a different file.
            var start = command.LastIndexOfAny(['"', '\'', '='], Math.Max(0, i - 1)) + 1;
            var reference = command[start..end];
            if (reference.Contains('%', StringComparison.Ordinal) || !DriveRegex().IsMatch(reference)) return true;
        }
        return false;
    }

    /// <summary>The path itself, not a longer one that starts the same way ("C:\App" is not in "C:\AppX\a.exe").</summary>
    private static bool ContainsPath(string text, string path)
    {
        for (var i = text.IndexOf(path, StringComparison.OrdinalIgnoreCase); i >= 0; i = text.IndexOf(path, i + 1, StringComparison.OrdinalIgnoreCase))
        {
            var end = i + path.Length;
            if (end >= text.Length || text[end] is '\\' or '"' or '\'' or ' ' or ',') return true;
        }
        return false;
    }

    /// <summary>The scheduled tasks, services and WMI processes a process asked Windows to create, from its command line.</summary>
    public static IEnumerable<LaunchRegistration> Registrations(ProcessNode node)
    {
        var cl = node.CommandLine;
        if (string.IsNullOrWhiteSpace(cl)) yield break;
        var name = node.Name.ToLowerInvariant();

        if (name is "schtasks.exe" or "schtasks")
        {
            var t = Tokenize(cl);
            if (t.Any(x => x.Equals("/create", StringComparison.OrdinalIgnoreCase) || x.Equals("-create", StringComparison.OrdinalIgnoreCase)))
            {
                var task = Option(t, "tn");
                if (task is not null) yield return new(PersistenceTechnique.ScheduledTask, task, Option(t, "tr") ?? string.Empty, node);
            }
        }
        else if (name is "sc.exe" or "sc")
        {
            var t = Tokenize(cl);
            var create = t.ToList().FindIndex(x => x.Equals("create", StringComparison.OrdinalIgnoreCase));
            if (create > 0 && create + 1 < t.Count)
            {
                string? bin = null;
                for (var i = create + 2; i < t.Count; i++)
                {
                    if (t[i].Equals("binpath=", StringComparison.OrdinalIgnoreCase) && i + 1 < t.Count) { bin = t[i + 1]; break; }
                    if (t[i].StartsWith("binpath=", StringComparison.OrdinalIgnoreCase) && t[i].Length > 8) { bin = t[i][8..]; break; }
                }
                yield return new(PersistenceTechnique.Service, t[create + 1], bin ?? string.Empty, node);
            }
        }
        else if (name is "wmic.exe" or "wmic")
        {
            if (WmicCreateRegex().Match(cl) is { Success: true } m) yield return new(null, null, Value(m).Trim(), node);
        }
        else if (name is "powershell.exe" or "pwsh.exe" or "powershell_ise.exe")
        {
            if (NewServiceRegex().IsMatch(cl) && PsNameRegex().Match(cl) is { Success: true } svc)
                yield return new(PersistenceTechnique.Service, Value(svc), PsBinaryRegex().Match(cl) is { Success: true } bin ? Value(bin) : string.Empty, node);
            if (RegisterTaskRegex().Match(cl) is { Success: true } task)
            {
                var exe = PsExecuteRegex().Match(cl);
                var args = PsArgumentRegex().Match(cl);
                var command = exe.Success ? (Value(exe) + (args.Success ? " " + Value(args) : string.Empty)) : string.Empty;
                yield return new(PersistenceTechnique.ScheduledTask, Value(task), command, node);
            }
            if (PsWmiCreateRegex().Match(cl) is { Success: true } wmi) yield return new(null, null, Value(wmi), node);
        }
    }

    /// <summary>The value after "/name" or "-name" (case-insensitive).</summary>
    private static string? Option(IReadOnlyList<string> tokens, string option)
    {
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            var t = tokens[i];
            if ((t.StartsWith('/') || t.StartsWith('-')) && t[1..].Equals(option, StringComparison.OrdinalIgnoreCase)) return tokens[i + 1];
        }
        return null;
    }

    private static string Value(Match m) => m.Groups["d"].Success ? m.Groups["d"].Value : m.Groups["s"].Success ? m.Groups["s"].Value : m.Groups["b"].Value;

    [GeneratedRegex(@"\s+")]
    private static partial Regex SpacesRegex();

    [GeneratedRegex(@"^(?<path>.+?\.(exe|com|bat|cmd|scr|pif|dll|ps1|vbs|vbe|js|jse|wsf|hta|msi))(?=[\s,]|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ProgramRegex();

    [GeneratedRegex(@"^[A-Za-z]:[\\/]|^\\\\")]
    private static partial Regex DriveRegex();

    [GeneratedRegex(@"process\s+call\s+create\s+(?:""(?<d>[^""]*)""|'(?<s>[^']*)'|(?<b>.+))", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex WmicCreateRegex();

    [GeneratedRegex(@"\bnew-service\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex NewServiceRegex();

    [GeneratedRegex(@"\s-name\s+(?:""(?<d>[^""]*)""|'(?<s>[^']*)'|(?<b>[^\s;]+))", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PsNameRegex();

    [GeneratedRegex(@"-binarypathname\s+(?:""(?<d>[^""]*)""|'(?<s>[^']*)'|(?<b>[^\s;]+))", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PsBinaryRegex();

    [GeneratedRegex(@"register-scheduledtask\b.*?-taskname\s+(?:""(?<d>[^""]*)""|'(?<s>[^']*)'|(?<b>[^\s;]+))", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RegisterTaskRegex();

    [GeneratedRegex(@"-execute\s+(?:""(?<d>[^""]*)""|'(?<s>[^']*)'|(?<b>[^\s;]+))", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PsExecuteRegex();

    [GeneratedRegex(@"-argument\s+(?:""(?<d>[^""]*)""|'(?<s>[^']*)'|(?<b>[^\s;]+))", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PsArgumentRegex();

    [GeneratedRegex(@"win32_process\b.*?(?:-argumentlist|commandline\s*=)\s*(?:""(?<d>[^""]*)""|'(?<s>[^']*)'|(?<b>[^\s;}]+))", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PsWmiCreateRegex();
}
