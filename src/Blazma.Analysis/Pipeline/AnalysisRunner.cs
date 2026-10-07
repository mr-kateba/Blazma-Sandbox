using System.Threading.Channels;
using Blazma.Analysis.Engine;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Samples;
using Blazma.Core.Snapshots;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blazma.Analysis.Pipeline;

public sealed record AnalysisRequest
{
    public required string SamplePath { get; init; }
    public required StaticReport Static { get; init; }
    public required AnalysisOptions Options { get; init; }
    public required EngineSettings EngineSettings { get; init; }
    public int MaxEvents { get; init; } = 250_000;
}

/// <summary>A progress update for the live screen. Sent on every stage change and periodically while analyzing.</summary>
public sealed record AnalysisProgress
{
    public required Guid AnalysisId { get; init; }
    public required AnalysisStage Stage { get; init; }
    public TimeSpan Elapsed { get; init; }
    public int EventCount { get; init; }
    public int ProcessCount { get; init; }
    public int ConnectionCount { get; init; }
    public int? LiveScore { get; init; }
    public Verdict? LiveVerdict { get; init; }
    public string? Message { get; init; }
    public bool MonitoringInterrupted { get; init; }
}

/// <summary>Raised when an analysis cannot continue. Carries a user-facing reason and diagnostics.</summary>
public sealed class AnalysisFailedException(string reason, Exception? inner = null) : Exception(reason, inner)
{
    public string Reason { get; } = reason;
}

/// <summary>
/// Drives one analysis through the state machine: provider session stages, live event
/// streaming, the analysis engine and storage. The environment is always shut down, on
/// success, failure and cancellation alike.
/// </summary>
public sealed class AnalysisRunner(AnalysisEngine engine, IAnalysisRepository repository, TimeProvider time, ILogger<AnalysisRunner>? logger = null)
{
    private readonly ILogger _logger = logger ?? NullLogger<AnalysisRunner>.Instance;
    private static readonly TimeSpan LiveScoreInterval = TimeSpan.FromSeconds(2);

    public async Task<AnalysisResult> RunAsync(
        AnalysisRequest request,
        ISandboxProvider provider,
        IProgress<AnalysisProgress>? progress,
        ChannelWriter<AnalysisEvent>? liveEvents,
        CancellationToken cancellationToken)
    {
        var options = request.Options.Normalized();
        var result = new AnalysisResult
        {
            AnalysisId = Guid.NewGuid(),
            Sample = request.Static.Sample,
            Static = request.Static,
            Options = options,
            ProviderId = provider.Id,
            IsDemo = provider.IsDemo,
            StartedAt = time.GetUtcNow(),
        };

        var stage = AnalysisStage.Preparing;
        var events = new List<AnalysisEvent>();
        var droppedForCap = 0;
        var lastLiveScore = DateTimeOffset.MinValue;
        int? liveScore = null;
        Verdict? liveVerdict = null;
        SystemSnapshot? baseline = null, after = null;
        ISandboxSession? session = null;

        void Report(string? message = null) => progress?.Report(new AnalysisProgress
        {
            AnalysisId = result.AnalysisId,
            Stage = stage,
            Elapsed = time.GetUtcNow() - result.StartedAt,
            EventCount = events.Count,
            ProcessCount = events.Count(e => e.Action == EventAction.ProcessStart),
            ConnectionCount = events.Count(e => e.Action == EventAction.NetworkConnect),
            LiveScore = liveScore,
            LiveVerdict = liveVerdict,
            Message = message,
            MonitoringInterrupted = result.MonitoringInterrupted,
        });

        void MoveTo(AnalysisStage next)
        {
            if (!AnalysisStateMachine.CanTransition(stage, next)) throw new InvalidStageTransitionException(stage, next);
            _logger.LogInformation("Analysis {AnalysisId}: {From} -> {To}", result.AnalysisId, stage, next);
            stage = next;
            Report();
        }

        try
        {
            Report();
            if (!result.Sample.IsExecutableKind)
                throw new AnalysisFailedException("Blazma cannot run this type of file. Supported types: EXE, DLL, MSI, PowerShell, batch and Windows script files, and shortcuts.");

            var availability = await provider.CheckAvailabilityAsync(cancellationToken).ConfigureAwait(false);
            if (!availability.IsReady)
            {
                var failed = availability.Checks.Where(c => !c.Passed).Select(c => c.Detail.En);
                throw new AnalysisFailedException("Unable to start the analysis environment. " + string.Join(" ", failed));
            }

            MoveTo(AnalysisStage.CreatingSandbox);
            session = await provider.CreateSessionAsync(new SandboxSessionRequest(result.AnalysisId, request.SamplePath, result.Sample, options), cancellationToken).ConfigureAwait(false);
            await session.CreateEnvironmentAsync(cancellationToken).ConfigureAwait(false);

            MoveTo(AnalysisStage.Booting);
            await session.BootAsync(cancellationToken).ConfigureAwait(false);

            MoveTo(AnalysisStage.DeployingAgent);
            await session.DeployAgentAsync(cancellationToken).ConfigureAwait(false);

            MoveTo(AnalysisStage.Ready);
            MoveTo(AnalysisStage.TransferringSample);
            await session.TransferSampleAsync(cancellationToken).ConfigureAwait(false);

            MoveTo(AnalysisStage.Analyzing);
            await foreach (var signal in session.ExecuteAsync(cancellationToken).ConfigureAwait(false))
            {
                switch (signal)
                {
                    case EventsSignal es:
                        foreach (var e in es.Events)
                        {
                            if (events.Count >= request.MaxEvents) { droppedForCap++; continue; }
                            events.Add(e);
                            liveEvents?.TryWrite(e);
                        }
                        break;
                    case MonitoringInterruptedSignal mi:
                        result.MonitoringInterrupted = true;
                        _logger.LogWarning("Analysis {AnalysisId}: monitoring interrupted ({Reason})", result.AnalysisId, mi.Reason);
                        break;
                }

                var now = time.GetUtcNow();
                if (now - lastLiveScore >= LiveScoreInterval && events.Count > 0)
                {
                    lastLiveScore = now;
                    (liveScore, liveVerdict) = ComputeLiveScore(result, events, request.EngineSettings);
                }
                Report();
            }

            MoveTo(AnalysisStage.CollectingEvents);
            var collected = await session.CollectAsync(cancellationToken).ConfigureAwait(false);
            foreach (var e in collected.RemainingEvents)
            {
                if (events.Count >= request.MaxEvents) { droppedForCap++; continue; }
                events.Add(e);
                liveEvents?.TryWrite(e);
            }
            baseline = collected.Baseline;
            after = collected.After;
            if (!collected.AgentCompleted && !result.MonitoringInterrupted)
            {
                result.MonitoringInterrupted = true;
            }

            MoveTo(AnalysisStage.Finalizing);
            await session.ShutdownAsync(cancellationToken).ConfigureAwait(false);

            MoveTo(AnalysisStage.GeneratingReport);
            if (droppedForCap > 0)
            {
                events.Add(Note(result, events, $"{droppedForCap} events were not stored because the per-analysis limit of {request.MaxEvents} was reached."));
            }
            if (result.MonitoringInterrupted && !events.Any(e => e.Action == EventAction.MonitoringInterrupted))
            {
                events.Add(new AnalysisEvent
                {
                    Sequence = NextSequence(events),
                    Timestamp = time.GetUtcNow(),
                    RelativeTime = events.Count == 0 ? TimeSpan.Zero : events.Max(e => e.RelativeTime),
                    Category = EventCategory.System,
                    Action = EventAction.MonitoringInterrupted,
                    ProcessName = "blazma",
                    Source = "host",
                    Severity = Severity.Medium,
                    Details = new Dictionary<string, string> { [DetailKeys.Reason] = "The agent did not report completion." },
                });
            }

            engine.Process(result, events, baseline, after, request.EngineSettings);
            result.CompletedAt = time.GetUtcNow();
            result.FinalStage = AnalysisStage.Completed;
            await repository.SaveAsync(result, CancellationToken.None).ConfigureAwait(false);

            MoveTo(AnalysisStage.Completed);
            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            stage = AnalysisStage.Cancelled;
            await FinishUnsuccessfulAsync(result, events, AnalysisStage.Cancelled, "The analysis was cancelled.", request).ConfigureAwait(false);
            Report("Cancelled");
            throw;
        }
        catch (Exception ex)
        {
            var reason = ex is AnalysisFailedException af ? af.Reason : $"The analysis failed: {ex.Message}";
            _logger.LogError(ex, "Analysis {AnalysisId} failed in stage {Stage}", result.AnalysisId, stage);
            stage = AnalysisStage.Failed;
            await FinishUnsuccessfulAsync(result, events, AnalysisStage.Failed, reason, request).ConfigureAwait(false);
            Report(reason);
            throw ex as AnalysisFailedException ?? new AnalysisFailedException(reason, ex);
        }
        finally
        {
            liveEvents?.TryComplete();
            if (session is not null)
            {
                try
                {
                    await session.ShutdownAsync(CancellationToken.None).ConfigureAwait(false);
                    await session.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Analysis {AnalysisId}: environment cleanup failed", result.AnalysisId);
                }
            }
        }
    }

    /// <summary>Failed and cancelled analyses are still recorded so History shows what happened.</summary>
    private async Task FinishUnsuccessfulAsync(AnalysisResult result, List<AnalysisEvent> events, AnalysisStage final, string reason, AnalysisRequest request)
    {
        result.FinalStage = final;
        result.FailureReason = reason;
        result.CompletedAt = time.GetUtcNow();
        try
        {
            if (events.Count > 0) engine.Process(result, events, null, null, request.EngineSettings);
            await repository.SaveAsync(result, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Could not record the {Stage} analysis {AnalysisId}", final, result.AnalysisId);
        }
    }

    private (int?, Verdict?) ComputeLiveScore(AnalysisResult result, List<AnalysisEvent> events, EngineSettings settings)
    {
        try
        {
            var scratch = new AnalysisResult
            {
                AnalysisId = result.AnalysisId,
                Sample = result.Sample,
                Static = result.Static,
                Options = result.Options,
                ProviderId = result.ProviderId,
                StartedAt = result.StartedAt,
                MonitoringInterrupted = result.MonitoringInterrupted,
            };
            engine.Process(scratch, events.ToList(), null, null, settings);
            return (scratch.Risk.Score, scratch.Risk.Verdict);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Live score computation failed");
            return (null, null);
        }
    }

    private static long NextSequence(List<AnalysisEvent> events) => events.Count == 0 ? 1 : events.Max(e => e.Sequence) + 1;

    private AnalysisEvent Note(AnalysisResult result, List<AnalysisEvent> events, string text) => new()
    {
        Sequence = NextSequence(events),
        Timestamp = time.GetUtcNow(),
        RelativeTime = events.Count == 0 ? TimeSpan.Zero : events.Max(e => e.RelativeTime),
        Category = EventCategory.System,
        Action = EventAction.AnalysisNote,
        ProcessName = "blazma",
        Source = "host",
        Details = new Dictionary<string, string> { [DetailKeys.Reason] = text },
    };
}
