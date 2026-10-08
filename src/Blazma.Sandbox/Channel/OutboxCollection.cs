using Blazma.Contracts;
using Blazma.Core.Abstractions;
using Blazma.Core.Events;
using Microsoft.Extensions.Logging;

namespace Blazma.Sandbox.Channel;

/// <summary>
/// The end-of-run collection every file-channel provider performs: remaining events, channel
/// problems as analysis notes, snapshots, screenshots, dropped files, memory regions and the
/// capture. Shared so providers cannot drift apart.
/// </summary>
public static class OutboxCollection
{
    /// <summary>Why monitoring should be reported as interrupted, or null when the channel looks healthy.</summary>
    public static string? InterruptionReason(OutboxReader reader, bool heartbeatLost, bool quotaExceeded = false) =>
        reader.TamperedFiles > 0 ? "Monitoring output failed its integrity check."
        : reader.QuotaExceeded || quotaExceeded ? "The sandbox exceeded the output quota."
        : heartbeatLost ? "The agent stopped sending heartbeats."
        : null;

    public static CollectedArtifacts Collect(
        OutboxReader reader,
        DateTimeOffset sampleStart,
        string artifactsFolder,
        AgentLimits limits,
        IEnumerable<string> extraProblems,
        ILogger logger)
    {
        var remaining = reader.ReadNewEvents(sampleStart).ToList();
        var done = reader.ReadDone();
        foreach (var problem in reader.Problems.Concat(extraProblems).Distinct().Take(20))
        {
            logger.LogWarning("Outbox: {Problem}", problem);
            remaining.Add(Note(problem, sampleStart, remaining.Count));
        }
        var screenshots = reader.ReadNewScreenshots(artifactsFolder);
        var dropped = reader.ReadDroppedFiles(artifactsFolder, limits.MaxDroppedFiles);
        var memory = reader.ReadMemoryRegions(artifactsFolder, Protocol.Limits.MaxMemoryRegions);
        var pcap = reader.ReadPcap(artifactsFolder);
        return new CollectedArtifacts(remaining, reader.ReadSnapshot(after: false), reader.ReadSnapshot(after: true), done is not null && done.Error is null)
        {
            Screenshots = screenshots,
            DroppedFiles = dropped,
            MemoryRegions = memory,
            PcapPath = pcap,
        };
    }

    /// <summary>A host-side note about the channel, shown in the timeline.</summary>
    public static AnalysisEvent Note(string problem, DateTimeOffset sampleStart, int index) => new()
    {
        Sequence = long.MaxValue - index,
        Timestamp = DateTimeOffset.UtcNow,
        RelativeTime = DateTimeOffset.UtcNow - sampleStart,
        Category = EventCategory.System,
        Action = EventAction.AnalysisNote,
        ProcessName = "blazma",
        Source = "host.channel",
        Severity = Severity.Medium,
        Details = new Dictionary<string, string> { [DetailKeys.Reason] = problem },
    };
}
