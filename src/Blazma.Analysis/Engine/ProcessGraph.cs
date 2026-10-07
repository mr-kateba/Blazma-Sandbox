using Blazma.Analysis.Text;
using Blazma.Core.Events;
using Blazma.Core.Processes;

namespace Blazma.Analysis.Engine;

/// <summary>
/// The process tree plus an index that answers "which process instance did this event
/// come from?" even when PIDs are reused.
/// </summary>
public sealed class ProcessGraph
{
    private readonly Dictionary<int, List<ProcessNode>> _byPid = [];
    private readonly Dictionary<ProcessKey, ProcessNode> _byKey = [];

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

        graph.Sample = graph._byKey.Values.Where(n => n.IsSample).OrderBy(n => n.Start).FirstOrDefault();
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
        if (parent is not null && parent != node)
        {
            node.ParentKey = parent.Key;
            parent.Children.Add(node);
        }
        else
        {
            Roots.Add(node);
        }

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
    /// The analyzed tree is the sample and its descendants, plus any process whose image
    /// the tree dropped (for example a service started by services.exe from a file the
    /// sample wrote), and their descendants. Iterates until nothing changes.
    /// </summary>
    private void MarkAnalyzedTree(IReadOnlyList<AnalysisEvent> events)
    {
        if (Sample is null) return;
        foreach (var n in Sample.SelfAndDescendants()) n.InAnalyzedTree = true;

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
                if (node.InAnalyzedTree) continue;
                foreach (var d in node.SelfAndDescendants())
                {
                    if (!d.InAnalyzedTree) { d.InAnalyzedTree = true; changed = true; }
                }
            }
            if (!changed) break;
        }
    }
}
