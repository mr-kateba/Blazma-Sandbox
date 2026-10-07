using Blazma.Core.Events;
using Blazma.Core.Text;

namespace Blazma.Core.Processes;

public enum ChainStepKind
{
    Started,
    Spawned,
    Dropped,
    Executed,
    ChangedRegistry,
    Persisted,
    ResolvedDomain,
    Connected,
    Deleted,
}

public sealed record ChainStep(ChainStepKind Kind, string Actor, string Target, TimeSpan Time, long EventSequence);

/// <summary>
/// A readable sequence of related actions: "setup.exe created updater.exe, ran it, and
/// updater.exe added itself to startup and contacted an external endpoint".
/// </summary>
public sealed record BehaviorChain(string Id, LocalizedText Title, Severity Severity, IReadOnlyList<ChainStep> Steps);
