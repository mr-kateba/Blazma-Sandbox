using System.Text.RegularExpressions;
using Blazma.Analysis.Text;
using Blazma.Core.Events;
using Blazma.Core.Processes;

namespace Blazma.Analysis.Engine;

/// <summary>
/// The process tree plus an index that answers "which process instance did this event
/// come from?" even when PIDs are reused.
/// </summary>
public sealed partial class ProcessGraph
{
    private readonly Dictionary<int, List<ProcessNode>> _byPid = [];
    private readonly Dictionary<ProcessKey, ProcessNode> _byKey = [];
    private readonly Dictionary<ProcessKey, int> _depth = [];

    /// <summary>
    /// The deepest level a process is nested at. A longer chain (a sample that keeps relaunching
    /// itself) continues as a new root that still names its parent, so the tree stays shallow
    /// enough to store, export and show. Without a limit, a few dozen levels already exceed what
    /// the stored report document can hold and the analysis fails while saving.
    /// </summary>
    public const int MaxTreeDepth = 100;

    public List<ProcessNode> Roots { get; } = [];
    public ProcessNode? Sample { get; private set; }
    public IReadOnlyDictionary<ProcessKey, ProcessNode> Nodes => _byKey;

    /// <summary>Files written by the analyzed tree, by normalised lower-case path, with the writing event.</summary>
    public Dictionary<string, AnalysisEvent> DroppedFiles { get; } = new(StringComparer.OrdinalIgnoreCase);

    public static ProcessGraph Build(IReadOnlyList<AnalysisEvent> orderedEvents)
    {
        var graph = new ProcessGraph();
        foreach (var e in orderedEvents)
        {
            switch (e.Action)
            {
                case EventAction.ProcessStart:
                    graph.AddStart(e);
                    break;
                case EventAction.ProcessExit:
                    if (graph.Resolve(e) is { } node)
                    {
                        node.End = e.RelativeTime;
                        if (int.TryParse(e.Detail(DetailKeys.ExitCode), out var code)) node.ExitCode = code;
                    }
                    break;
            }
        }

        // The agent marks every process it starts after the sample as the sample (its packet capture
        // stops after the run), so the earliest one that is not an agent helper is the real sample.
        graph.Sample = graph._byKey.Values.Where(n => n.IsSample && !IsAgentHelper(n)).OrderBy(n => n.Start).FirstOrDefault();
        if (graph.Sample is null)
        {
            var executed = orderedEvents.FirstOrDefault(e => e.Action == EventAction.SampleExecuted);
            if (executed is not null) graph.Sample = graph.Resolve(executed);
        }

        graph.MarkAnalyzedTree(orderedEvents);
        return graph;
    }

    private void AddStart(AnalysisEvent e)
    {
        var key = e.Process ?? new ProcessKey(e.ProcessId, e.RelativeTime.Ticks);
        if (_byKey.ContainsKey(key)) return;
        var image = e.Detail(DetailKeys.ImagePath);
        var node = new ProcessNode
        {
            Key = key,
            Pid = e.ProcessId,
            ParentPid = e.ParentProcessId,
            Name = string.IsNullOrEmpty(e.ProcessName) ? PathRules.FileName(image) : e.ProcessName,
            ImagePath = image is null ? null : PathRules.NormalizeFilePath(image),
            CommandLine = e.Detail(DetailKeys.CommandLine),
            User = e.Detail(DetailKeys.User),
            IntegrityLevel = e.Detail(DetailKeys.IntegrityLevel),
            Architecture = e.Detail(DetailKeys.Architecture),
            Sha256 = e.Detail(DetailKeys.Sha256),
            Signer = e.Detail(DetailKeys.Signer),
            Start = e.RelativeTime,
            IsSample = string.Equals(e.Detail(DetailKeys.IsSample), "true", StringComparison.OrdinalIgnoreCase),
            StartEventSequence = e.Sequence,
        };

        var parent = FindLive(e.ParentProcessId, e.RelativeTime);
        var depth = 1;
        if (parent is not null && parent != node)
        {
            node.ParentKey = parent.Key;
            depth = _depth[parent.Key] + 1;
        }
        if (parent is not null && parent != node && depth <= MaxTreeDepth)
        {
            parent.Children.Add(node);
        }
        else
        {
            depth = 1;
            Roots.Add(node);
        }
        _depth[key] = depth;

        _byKey[key] = node;
        if (!_byPid.TryGetValue(e.ProcessId, out var list)) _byPid[e.ProcessId] = list = [];
        list.Add(node);
    }

    private ProcessNode? FindLive(int pid, TimeSpan at)
    {
        if (!_byPid.TryGetValue(pid, out var list)) return null;
        for (var i = list.Count - 1; i >= 0; i--)
        {
            var n = list[i];
            if (n.Start <= at && (n.End is null || n.End >= at)) return n;
        }
        return null;
    }

    /// <summary>The process instance an event belongs to, or null for unknown (pre-existing) processes.</summary>
    public ProcessNode? Resolve(AnalysisEvent e)
    {
        if (e.Process is { } key && _byKey.TryGetValue(key, out var exact)) return exact;
        if (!_byPid.TryGetValue(e.ProcessId, out var list) || list.Count == 0) return null;
        return FindLive(e.ProcessId, e.RelativeTime) ?? list.LastOrDefault(n => n.Start <= e.RelativeTime);
    }

    public bool InAnalyzedTree(AnalysisEvent e) => Resolve(e)?.InAnalyzedTree == true;

    /// <summary>
    /// The analyzed tree is the sample and its descendants, plus processes Windows started for it:
    /// any process whose image the tree dropped (for example a service started by services.exe
    /// from a file the sample wrote), the Windows Installer service while the tree runs msiexec,
    /// and services, tasks or WMI processes whose command the tree registered; with their
    /// descendants. Console hosts and crash reporters Windows attaches by itself are left out.
    /// Iterates until nothing changes.
    /// </summary>
    private void MarkAnalyzedTree(IReadOnlyList<AnalysisEvent> events)
    {
        if (Sample is null) return;
        MarkSubtree(Sample);
        MarkContinuedChains();

        for (var pass = 0; pass < 5; pass++)
        {
            var changed = false;
            foreach (var e in events)
            {
                if (e.Action is not (EventAction.FileCreate or EventAction.FileWrite or EventAction.FileRename)) continue;
                var path = e.Action == EventAction.FileRename ? e.Detail(DetailKeys.NewPath) ?? e.Target : e.Target;
                if (string.IsNullOrEmpty(path) || !InAnalyzedTree(e)) continue;
                DroppedFiles.TryAdd(PathRules.NormalizeFilePath(path), e);
            }

            foreach (var node in _byKey.Values)
            {
                if (node.ImagePath is null || !DroppedFiles.TryGetValue(node.ImagePath, out var drop)) continue;
                if (drop.RelativeTime > node.Start) continue;
                node.ImageDroppedDuringAnalysis = true;
                if (!node.InAnalyzedTree && MarkSubtree(node)) changed = true;
            }
            if (MarkContinuedChains()) changed = true;
            if (MarkWindowsInstaller()) changed = true;
            if (MarkLaunchedOnBehalf(events)) changed = true;
            if (!changed) break;
        }
    }

    /// <summary>Marks a process and its descendants, skipping the helpers Windows attaches by itself. True when anything changed.</summary>
    private static bool MarkSubtree(ProcessNode root)
    {
        var changed = false;
        var stack = new Stack<ProcessNode>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            if (n != root && IsAutomaticHelper(n)) continue;
            if (!n.InAnalyzedTree) { n.InAnalyzedTree = true; changed = true; }
            foreach (var c in n.Children) stack.Push(c);
        }
        return changed;
    }

    /// <summary>
    /// The console host Windows starts for every console program and the crash reporter it starts
    /// when one fails. Neither does anything the sample asked for. A console host started with
    /// other arguments ("conhost --headless cmd ...") is a known way to run commands, and stays.
    /// </summary>
    internal static bool IsAutomaticHelper(ProcessNode n) =>
        (n.Name.Equals("conhost.exe", StringComparison.OrdinalIgnoreCase) && n.CommandLine is { } cl && AutomaticConsoleRegex().IsMatch(cl))
        || ((n.Name.Equals("WerFault.exe", StringComparison.OrdinalIgnoreCase) || n.Name.Equals("WerFaultSecure.exe", StringComparison.OrdinalIgnoreCase))
            && n.ImagePath?.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) == true);

    /// <summary>Programs the in-sandbox agent runs itself (packet capture).</summary>
    internal static bool IsAgentHelper(ProcessNode n) => n.Name.Equals("pktmon.exe", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// msiexec in the tree only asks the Windows Installer service to install; the service (msiexec /V,
    /// started by services.exe) and its custom-action servers (msiexec -Embedding) do the work.
    /// </summary>
    private bool MarkWindowsInstaller()
    {
        var client = _byKey.Values.Where(n => n.InAnalyzedTree && IsMsiexec(n)).OrderBy(n => n.Start).FirstOrDefault();
        if (client is null) return false;
        var changed = false;
        foreach (var n in _byKey.Values)
        {
            if (n.InAnalyzedTree || !IsMsiexec(n) || n.Start < client.Start || n.CommandLine is null || !MsiServerRegex().IsMatch(n.CommandLine)) continue;
            if (MarkSubtree(n)) changed = true;
        }
        return changed;
    }

    private static bool IsMsiexec(ProcessNode n) => n.Name.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// A process started by Windows (services.exe, the Task Scheduler, WMI) whose command line is
    /// one the tree registered: with schtasks /create /tr, sc create binPath=, New-Service,
    /// Register-ScheduledTask, wmic process call create, or a service image path the tree wrote.
    /// </summary>
    private bool MarkLaunchedOnBehalf(IReadOnlyList<AnalysisEvent> events)
    {
        var registered = new List<(string Command, TimeSpan From)>();
        var serviceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var n in _byKey.Values.Where(n => n.InAnalyzedTree))
        {
            foreach (var r in CommandLines.Registrations(n))
            {
                if (r.Command.Length > 0) registered.Add((r.Command, n.Start));
                if (r.Technique == PersistenceTechnique.Service && r.Name is not null) serviceNames.Add(r.Name);
            }
        }
        foreach (var e in events)
        {
            if (e.Action != EventAction.RegistryValueSet || e.Target is null || e.Detail(DetailKeys.ValueData) is not { Length: > 0 } data) continue;
            if (!string.Equals(e.Detail(DetailKeys.ValueName), "ImagePath", StringComparison.OrdinalIgnoreCase)) continue;
            if (ServiceKeyRegex().Match(PathRules.NormalizeRegistryKey(e.Target)) is not { Success: true } m) continue;
            if (InAnalyzedTree(e) || serviceNames.Contains(m.Groups["name"].Value)) registered.Add((data, e.RelativeTime));
        }
        if (registered.Count == 0) return false;

        var changed = false;
        foreach (var node in _byKey.Values)
        {
            if (node.InAnalyzedTree || node.CommandLine is null) continue;
            if (registered.Any(r => node.Start >= r.From && Launches(r.Command, node)) && MarkSubtree(node)) changed = true;
        }
        return changed;
    }

    /// <summary>Whether a process is the one a registered command starts. Shared hosts such as svchost never count: their command lines are not specific.</summary>
    private static bool Launches(string command, ProcessNode node)
    {
        var exe = PathRules.NormalizeFilePath(CommandLines.ExecutablePath(command));
        if (PathRules.FileName(exe).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)) return false;
        var wanted = CommandLines.Normalize(command);
        if (wanted.Length >= 12 && wanted == CommandLines.Normalize(node.CommandLine)) return true;
        // A program in a user folder or written by the tree: the same file is enough (arguments may be quoted differently).
        // Programs of Windows or of installed software run on their own too, so for them only the whole command counts.
        return node.ImagePath is not null && node.ImagePath.Equals(exe, StringComparison.OrdinalIgnoreCase)
            && (node.ImageDroppedDuringAnalysis || PathRules.IsUserWritableLocation(exe));
    }

    [GeneratedRegex(@"conhost\.exe""?\s+0x[0-9a-f]+(\s+-forcev1)?\s*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AutomaticConsoleRegex();

    [GeneratedRegex(@"(^|\s)[/-](v|embedding)(\s|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MsiServerRegex();

    [GeneratedRegex(@"^HKLM\\System\\(CurrentControlSet|ControlSet\d{3})\\Services\\(?<name>[^\\]+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ServiceKeyRegex();

    /// <summary>A chain continued as a new root (see <see cref="MaxTreeDepth"/>) belongs to the analyzed tree when its parent does.</summary>
    private bool MarkContinuedChains()
    {
        var changed = false;
        foreach (var root in Roots) // in start order, so a continuation's parent is settled before it
        {
            if (root.InAnalyzedTree || root.ParentKey is not { } pk || !_byKey.TryGetValue(pk, out var parent) || !parent.InAnalyzedTree) continue;
            if (MarkSubtree(root)) changed = true;
        }
        return changed;
    }
}
