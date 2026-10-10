using System.Text.Json.Serialization;
using Blazma.Core.Events;

namespace Blazma.Core.Processes;

/// <summary>One process seen during the analysis, with its place in the tree.</summary>
public sealed class ProcessNode
{
    public required ProcessKey Key { get; init; }
    public ProcessKey? ParentKey { get; set; }
    public required int Pid { get; init; }
    public int ParentPid { get; init; }
    public required string Name { get; init; }
    public string? ImagePath { get; init; }
    public string? CommandLine { get; init; }
    public string? User { get; init; }
    public string? IntegrityLevel { get; init; }
    public string? Architecture { get; init; }
    public string? Sha256 { get; init; }
    public string? Signer { get; init; }
    public TimeSpan Start { get; init; }
    public TimeSpan? End { get; set; }
    public int? ExitCode { get; set; }

    /// <summary>The submitted sample itself.</summary>
    public bool IsSample { get; init; }

    /// <summary>The sample or one of its descendants. Everything else is background activity.</summary>
    public bool InAnalyzedTree { get; set; }

    /// <summary>The image was written to disk by a process in the analyzed tree during the analysis.</summary>
    public bool ImageDroppedDuringAnalysis { get; set; }

    public long StartEventSequence { get; init; }

    [JsonObjectCreationHandling(JsonObjectCreationHandling.Populate)] // each node owns its list, so filling it in place is safe
    public List<ProcessNode> Children { get; } = [];

    /// <summary>
    /// This node and everything below it, depth first in child order. Iterative: a long chain of
    /// processes (a sample that keeps relaunching itself) must not exhaust the stack.
    /// </summary>
    public IEnumerable<ProcessNode> SelfAndDescendants()
    {
        var stack = new Stack<ProcessNode>();
        stack.Push(this);
        while (stack.Count > 0)
        {
            var node = stack.Pop();
            yield return node;
            for (var i = node.Children.Count - 1; i >= 0; i--) stack.Push(node.Children[i]);
        }
    }
}
