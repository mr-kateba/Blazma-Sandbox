using Blazma.Analysis.Text;
using Blazma.Core.Events;
using Blazma.Core.Processes;
using Blazma.Core.Text;

namespace Blazma.Analysis.Engine;

/// <summary>
/// Turns separate events into behaviour chains. For every process in the analyzed tree
/// that did something significant (persistence, external connections, running a dropped
/// file), it walks back to the sample and writes the path as a readable sequence.
/// </summary>
public static class CorrelationEngine
{
    private const int MaxChains = 25;
    private const int MaxActionsPerChain = 12;

    public static IReadOnlyList<BehaviorChain> BuildChains(
        IReadOnlyList<AnalysisEvent> events,
        ProcessGraph graph,
        IReadOnlyList<PersistenceDetection> persistence,
        NetworkMap network)
    {
        if (graph.Sample is null) return [];

        var actions = new Dictionary<ProcessKey, List<ChainStep>>();
        void AddAction(ProcessNode node, ChainStep step)
        {
            if (!actions.TryGetValue(node.Key, out var list)) actions[node.Key] = list = [];
            if (list.Count < MaxActionsPerChain && !list.Any(s => s.Kind == step.Kind && s.Target.Equals(step.Target, StringComparison.OrdinalIgnoreCase)))
                list.Add(step);
        }

        foreach (var p in persistence.Where(p => p.ByAnalyzedTree && p.Process is not null))
        {
            if (graph.Nodes.TryGetValue(p.Process!.Value, out var node))
                AddAction(node, new ChainStep(ChainStepKind.Persisted, node.Name, $"{PersistenceCatalog.Name(p.Technique).En}: {p.Target}", p.Time, p.EventSequences[0]));
        }

        foreach (var e in events)
        {
            if (graph.Resolve(e) is not { InAnalyzedTree: true } node) continue;
            switch (e.Action)
            {
                case EventAction.NetworkConnect when NetworkMap.IsExternal(e):
                {
                    var endpoint = NetworkMap.Endpoint(e);
                    var domain = network.DomainFor(e.Detail(DetailKeys.RemoteAddress));
                    AddAction(node, new ChainStep(ChainStepKind.Connected, node.Name, domain is null ? endpoint : $"{domain} ({endpoint})", e.RelativeTime, e.Sequence));
                    break;
                }
                case EventAction.FileDelete when node.IsSample && e.Target is not null && node.ImagePath is not null
                                                 && PathRules.NormalizeFilePath(e.Target).Equals(node.ImagePath, StringComparison.OrdinalIgnoreCase):
                    AddAction(node, new ChainStep(ChainStepKind.Deleted, node.Name, PathRules.FileName(e.Target), e.RelativeTime, e.Sequence));
                    break;
            }
        }

        // A dropped program that was run is significant on its own.
        foreach (var node in graph.Nodes.Values.Where(n => n.InAnalyzedTree && n.ImageDroppedDuringAnalysis && !actions.ContainsKey(n.Key)))
            actions[node.Key] = [];

        var chains = new List<BehaviorChain>();
        foreach (var (key, list) in actions.OrderBy(a => graph.Nodes[a.Key].Start))
        {
            if (chains.Count >= MaxChains) break;
            var actor = graph.Nodes[key];
            var steps = Ancestry(actor, graph);
            steps.AddRange(list.OrderBy(s => s.Time));
            if (steps.Count < 2) continue;

            var hasPersist = list.Any(s => s.Kind == ChainStepKind.Persisted);
            var hasConnect = list.Any(s => s.Kind == ChainStepKind.Connected);
            var hasDrop = steps.Any(s => s.Kind == ChainStepKind.Dropped);
            var severity = hasPersist && hasConnect && hasDrop ? Severity.Critical
                : hasPersist ? Severity.High
                : hasConnect || hasDrop ? Severity.Medium
                : Severity.Low;

            chains.Add(new BehaviorChain(
                $"chain-{chains.Count + 1}",
                new LocalizedText($"What {actor.Name} did", $"ما الذي فعله {actor.Name}"),
                severity,
                steps));
        }
        return chains;
    }

    /// <summary>From the sample down to the actor, describing each hop as "spawned" or "dropped then executed".</summary>
    private static List<ChainStep> Ancestry(ProcessNode actor, ProcessGraph graph)
    {
        var path = new List<ProcessNode>();
        for (var n = actor; n is not null; n = n.ParentKey is { } pk && graph.Nodes.TryGetValue(pk, out var p) ? p : null)
        {
            path.Add(n);
            if (n.IsSample || path.Count > 32) break;
        }
        path.Reverse();

        var steps = new List<ChainStep>();
        var root = path[0];
        steps.Add(new ChainStep(ChainStepKind.Started, root.Name, root.Name, root.Start, root.StartEventSequence));
        for (var i = 1; i < path.Count; i++)
        {
            var parent = path[i - 1];
            var child = path[i];
            if (child.ImageDroppedDuringAnalysis && child.ImagePath is not null && graph.DroppedFiles.TryGetValue(child.ImagePath, out var drop))
            {
                var dropper = graph.Resolve(drop);
                steps.Add(new ChainStep(ChainStepKind.Dropped, dropper?.Name ?? drop.ProcessName, PathRules.FileName(child.ImagePath), drop.RelativeTime, drop.Sequence));
                steps.Add(new ChainStep(ChainStepKind.Executed, parent.Name, child.Name, child.Start, child.StartEventSequence));
            }
            else
            {
                steps.Add(new ChainStep(ChainStepKind.Spawned, parent.Name, child.Name, child.Start, child.StartEventSequence));
            }
        }
        return steps;
    }
}
