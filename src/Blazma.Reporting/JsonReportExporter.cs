using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Processes;
using Blazma.Storage;

namespace Blazma.Reporting;

/// <summary>
/// Machine-readable report. Layout:
/// <code>{ "format": "blazma-sandbox-report", "formatVersion": 1, ..., "integrity": { "contentSha256": "…" }, "content": { … } }</code>
/// The hash covers the exact bytes of <c>content</c>, so anyone can confirm a report was
/// not edited after export (see <see cref="ReportIntegrity"/>).
/// </summary>
public sealed class JsonReportExporter : IReportExporter
{
    public const string FormatName = "blazma-sandbox-report";
    public const int FormatVersion = 1;

    private readonly Func<bool, Redactor> _redactorFactory;

    public JsonReportExporter(Func<bool, Redactor>? redactorFactory = null)
    {
        _redactorFactory = redactorFactory ?? (redact => redact ? new Redactor() : Redactor.None);
    }

    public string Format => "JSON";
    public string FileExtension => ".json";

    public async Task ExportAsync(AnalysisResult result, Stream destination, ExportOptions options, CancellationToken cancellationToken)
    {
        var r = _redactorFactory(options.Redact);
        var content = BuildContent(result, options, r);
        var contentBytes = JsonSerializer.SerializeToUtf8Bytes(content, BlazmaJson.Indented);
        var hash = Convert.ToHexStringLower(SHA256.HashData(contentBytes));

        var header = new StringBuilder();
        header.Append("{\n");
        header.Append($"  \"format\": \"{FormatName}\",\n");
        header.Append($"  \"formatVersion\": {FormatVersion},\n");
        header.Append($"  \"generator\": {JsonSerializer.Serialize("Blazma Sandbox " + typeof(JsonReportExporter).Assembly.GetName().Version?.ToString(3))},\n");
        header.Append($"  \"generatedAt\": {JsonSerializer.Serialize(DateTimeOffset.UtcNow)},\n");
        header.Append($"  \"language\": {JsonSerializer.Serialize(options.Language)},\n");
        header.Append($"  \"redacted\": {(options.Redact ? "true" : "false")},\n");
        header.Append($"  \"demo\": {(result.IsDemo ? "true" : "false")},\n");
        header.Append($"  \"disclaimer\": {JsonSerializer.Serialize(RiskAssessment.Disclaimer)},\n");
        header.Append($"  \"integrity\": {{ \"algorithm\": \"SHA-256\", \"contentSha256\": \"{hash}\" }},\n");
        header.Append("  \"content\": ");

        await destination.WriteAsync(Encoding.UTF8.GetBytes(header.ToString()), cancellationToken).ConfigureAwait(false);
        await destination.WriteAsync(contentBytes, cancellationToken).ConfigureAwait(false);
        await destination.WriteAsync("\n}\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    internal static object BuildContent(AnalysisResult a, ExportOptions o, Redactor r)
    {
        var lang = o.Language;
        return new
        {
            analysis = new
            {
                id = a.AnalysisId,
                provider = a.ProviderId,
                startedAt = a.StartedAt,
                completedAt = a.CompletedAt,
                durationSeconds = a.Duration?.TotalSeconds,
                stage = a.FinalStage.ToString(),
                failureReason = r.Apply(a.FailureReason),
                monitoringInterrupted = a.MonitoringInterrupted,
                suppressedNoiseEvents = a.SuppressedNoiseEvents,
                options = a.Options,
            },
            sample = new
            {
                fileName = r.Apply(a.Sample.FileName),
                size = a.Sample.Size,
                sha256 = a.Sample.Sha256,
                sha1 = a.Sample.Sha1,
                kind = a.Sample.Kind.ToString(),
            },
            staticAnalysis = o.IncludeStatic && a.Static is { } s ? new
            {
                entropy = s.Entropy,
                signature = new { status = s.Signature.Status.ToString(), publisher = s.Signature.Publisher, detail = s.Signature.Detail },
                pe = s.Pe is null ? null : new
                {
                    s.Pe.Machine,
                    s.Pe.Is64Bit,
                    s.Pe.IsDll,
                    s.Pe.Subsystem,
                    s.Pe.IsDotNet,
                    compileTimestamp = s.Pe.CompileTimestamp,
                    compileTimestampNote = "Compile timestamps are set by the build tool and can be forged.",
                    sections = s.Pe.Sections,
                    imports = s.Pe.Imports.Select(i => new { library = i.Library, functions = i.Functions }),
                    exports = s.Pe.Exports,
                    s.Pe.ResourceCount,
                    versionInfo = s.Pe.VersionInfo,
                    s.Pe.HasOverlay,
                },
                strings = s.Strings.Select(x => new { kind = x.Kind.ToString(), value = r.Apply(x.Value) }),
                warnings = s.Warnings,
            } : null,
            risk = new
            {
                score = a.Risk.Score,
                verdict = a.Risk.Verdict.ToString(),
                verdictText = VerdictText.Of(a.Risk.Verdict, lang),
                contributions = a.Risk.Contributions.Select(c => new { c.RuleId, title = c.Title.Get(lang), category = c.Category.ToString(), c.Points, c.Capped }),
            },
            findings = a.Findings.Select(f => new
            {
                f.Id,
                f.RuleId,
                f.RuleVersion,
                title = f.Title.Get(lang),
                explanation = f.Explanation.Get(lang),
                category = f.Category.ToString(),
                severity = f.Severity.ToString(),
                f.Points,
                provenance = f.Provenance.ToString(),
                attack = f.AttackTechniques,
                firstSeenMs = f.FirstSeen?.TotalMilliseconds,
                evidence = f.Evidence.Select(e => new
                {
                    e.Kind,
                    description = r.Apply(e.Description.Get(lang)),
                    technical = r.Apply(e.Technical),
                    events = e.EventSequences,
                }),
            }),
            chains = a.Chains.Select(c => new
            {
                c.Id,
                title = r.Apply(c.Title.Get(lang)),
                severity = c.Severity.ToString(),
                steps = c.Steps.Select(st => new { kind = st.Kind.ToString(), actor = r.Apply(st.Actor), target = r.Apply(st.Target), timeMs = st.Time.TotalMilliseconds, @event = st.EventSequence }),
            }),
            processTree = a.ProcessRoots.Select(n => Node(n, r)),
            persistence = a.Persistence.Select(p => new
            {
                technique = p.Technique.ToString(),
                process = r.Apply(p.ProcessName),
                target = r.Apply(p.Target),
                value = r.Apply(p.Value),
                timeMs = p.Time.TotalMilliseconds,
                severity = p.Severity.ToString(),
                explanation = p.Explanation.Get(lang),
                byAnalyzedTree = p.ByAnalyzedTree,
                pointsToDroppedFile = p.PointsToDroppedFile,
                events = p.EventSequences,
            }),
            indicators = o.IncludeIndicators ? a.Indicators.Select(i => new { type = i.Type.ToString(), value = r.Apply(i.Value), status = i.Status.ToString(), i.Source, events = i.EventSequences }) : null,
            systemChanges = a.SystemChanges is null ? null : new
            {
                files = new { created = a.SystemChanges.FilesCreated.Select(f => r.Apply(f.Path)), modified = a.SystemChanges.FilesModified.Select(f => r.Apply(f.Path)), deleted = a.SystemChanges.FilesDeleted.Select(f => r.Apply(f.Path)) },
                registry = new
                {
                    added = a.SystemChanges.RegistryAdded.Select(x => new { key = r.Apply(x.Key), x.ValueName, data = r.Apply(x.NewData) }),
                    modified = a.SystemChanges.RegistryModified.Select(x => new { key = r.Apply(x.Key), x.ValueName, oldData = r.Apply(x.OldData), newData = r.Apply(x.NewData) }),
                    removed = a.SystemChanges.RegistryRemoved.Select(x => new { key = r.Apply(x.Key), x.ValueName }),
                },
                services = new { added = a.SystemChanges.ServicesAdded, removed = a.SystemChanges.ServicesRemoved },
                scheduledTasks = new { added = a.SystemChanges.TasksAdded, removed = a.SystemChanges.TasksRemoved },
                startup = new { added = a.SystemChanges.StartupAdded.Select(r.Apply), removed = a.SystemChanges.StartupRemoved.Select(r.Apply) },
            },
            timeline = o.IncludeTimeline ? TimelineSummary(a, o.TimelineLimit).Select(e => Event(e, r)) : null,
            events = o.IncludeRawEvents ? a.Events.Select(e => Event(e, r)) : null,
        };
    }

    /// <summary>The events worth reading first: everything the findings cite, then the rest in order, up to the limit.</summary>
    internal static IReadOnlyList<AnalysisEvent> TimelineSummary(AnalysisResult a, int limit)
    {
        var cited = a.Findings.SelectMany(f => f.AllEventSequences).ToHashSet();
        return a.Events
            .Where(e => cited.Contains(e.Sequence) || e.Severity >= Severity.Medium || e.Action is EventAction.ProcessStart or EventAction.NetworkConnect or EventAction.DnsQuery)
            .Take(Math.Max(1, limit))
            .ToList();
    }

    private static object Event(AnalysisEvent e, Redactor r) => new
    {
        seq = e.Sequence,
        timeMs = e.RelativeTime.TotalMilliseconds,
        category = e.Category.ToString(),
        action = e.Action.ToString(),
        pid = e.ProcessId,
        ppid = e.ParentProcessId,
        process = r.Apply(e.ProcessName),
        target = r.Apply(e.Target),
        details = e.Details.ToDictionary(kv => kv.Key, kv => r.Apply(kv.Value)),
        severity = e.Severity.ToString(),
        source = e.Source,
    };

    private static object Node(ProcessNode n, Redactor r) => new
    {
        pid = n.Pid,
        ppid = n.ParentPid,
        name = r.Apply(n.Name),
        image = r.Apply(n.ImagePath),
        commandLine = r.Apply(n.CommandLine),
        user = r.Apply(n.User),
        integrity = n.IntegrityLevel,
        startMs = n.Start.TotalMilliseconds,
        endMs = n.End?.TotalMilliseconds,
        exitCode = n.ExitCode,
        isSample = n.IsSample,
        inAnalyzedTree = n.InAnalyzedTree,
        droppedDuringAnalysis = n.ImageDroppedDuringAnalysis,
        children = n.Children.Select(c => Node(c, r)),
    };
}

public static class ReportIntegrity
{
    /// <summary>Checks a JSON report's content hash. Returns false if the content was edited.</summary>
    public static bool Verify(string json)
    {
        // Deep process trees nest well past the default depth of 64 (the store allows 256).
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 256 });
        if (!doc.RootElement.TryGetProperty("content", out var content)) return false;
        if (!doc.RootElement.TryGetProperty("integrity", out var integrity) || !integrity.TryGetProperty("contentSha256", out var expected)) return false;
        var actual = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content.GetRawText())));
        return string.Equals(actual, expected.GetString(), StringComparison.Ordinal);
    }
}
