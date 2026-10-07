namespace Blazma.Core.Analysis;

/// <summary>Every state an analysis can be in. See <see cref="AnalysisStateMachine"/>.</summary>
public enum AnalysisStage
{
    Preparing,
    CreatingSandbox,
    Booting,
    DeployingAgent,
    Ready,
    TransferringSample,
    Analyzing,
    CollectingEvents,
    Finalizing,
    GeneratingReport,
    Completed,
    Failed,
    Cancelled,
}

/// <summary>
/// The allowed transitions. The happy path is strictly linear; any non-terminal state may
/// move to <see cref="AnalysisStage.Failed"/> or <see cref="AnalysisStage.Cancelled"/>.
/// Terminal states never move again.
/// </summary>
public static class AnalysisStateMachine
{
    private static readonly AnalysisStage[] HappyPath =
    [
        AnalysisStage.Preparing,
        AnalysisStage.CreatingSandbox,
        AnalysisStage.Booting,
        AnalysisStage.DeployingAgent,
        AnalysisStage.Ready,
        AnalysisStage.TransferringSample,
        AnalysisStage.Analyzing,
        AnalysisStage.CollectingEvents,
        AnalysisStage.Finalizing,
        AnalysisStage.GeneratingReport,
        AnalysisStage.Completed,
    ];

    public static IReadOnlyList<AnalysisStage> Path => HappyPath;

    public static bool IsTerminal(AnalysisStage stage) =>
        stage is AnalysisStage.Completed or AnalysisStage.Failed or AnalysisStage.Cancelled;

    public static bool CanTransition(AnalysisStage from, AnalysisStage to)
    {
        if (IsTerminal(from)) return false;
        if (to is AnalysisStage.Failed or AnalysisStage.Cancelled) return true;
        var i = Array.IndexOf(HappyPath, from);
        return i >= 0 && i + 1 < HappyPath.Length && HappyPath[i + 1] == to;
    }

    /// <summary>Position in the happy path, used for progress bars. Terminal failure states return -1.</summary>
    public static int IndexOf(AnalysisStage stage) => Array.IndexOf(HappyPath, stage);
}

/// <summary>Thrown when code tries to make a transition the state machine does not allow.</summary>
public sealed class InvalidStageTransitionException(AnalysisStage from, AnalysisStage to)
    : InvalidOperationException($"Analysis cannot move from {from} to {to}.")
{
    public AnalysisStage From { get; } = from;
    public AnalysisStage To { get; } = to;
}
