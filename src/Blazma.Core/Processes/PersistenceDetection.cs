using Blazma.Core.Events;
using Blazma.Core.Text;

namespace Blazma.Core.Processes;

public enum PersistenceTechnique
{
    RunKey,
    StartupFolder,
    ScheduledTask,
    Service,
    WinlogonHelper,
    ImageFileExecutionOptions,
    AppInitDlls,
    ActiveSetup,
    Other,
}

public sealed record PersistenceDetection
{
    public required PersistenceTechnique Technique { get; init; }
    public required string ProcessName { get; init; }
    public ProcessKey? Process { get; init; }
    public required string Target { get; init; }
    public string? Value { get; init; }
    public required TimeSpan Time { get; init; }
    public required Severity Severity { get; init; }
    public required LocalizedText Explanation { get; init; }
    public required IReadOnlyList<long> EventSequences { get; init; }

    /// <summary>The persisted command points at a file the analyzed tree dropped.</summary>
    public bool PointsToDroppedFile { get; init; }

    public bool ByAnalyzedTree { get; init; }
}
