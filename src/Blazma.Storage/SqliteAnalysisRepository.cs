using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Samples;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blazma.Storage;

/// <summary>SQLite-backed history. One connection per operation; WAL mode for concurrent reads during writes.</summary>
public sealed class SqliteAnalysisRepository : IAnalysisRepository
{
    private readonly string _connectionString;
    private readonly ILogger _logger;

    public SqliteAnalysisRepository(string databasePath, ILogger<SqliteAnalysisRepository>? logger = null)
    {
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = true,
        }.ToString();
        _logger = logger ?? NullLogger<SqliteAnalysisRepository>.Instance;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken ct)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        await connection.ExecuteAsync("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;").ConfigureAwait(false);
        return connection;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await using var c = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await c.ExecuteAsync("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)").ConfigureAwait(false);
        var current = await c.ExecuteScalarAsync<int?>("SELECT MAX(version) FROM schema_version").ConfigureAwait(false) ?? 0;
        for (var v = current; v < Schema.Migrations.Length; v++)
        {
            await using var tx = await c.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            await c.ExecuteAsync(Schema.Migrations[v], transaction: tx).ConfigureAwait(false);
            await c.ExecuteAsync("INSERT INTO schema_version(version) VALUES (@v)", new { v = v + 1 }, tx).ConfigureAwait(false);
            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("Database migrated to schema version {Version}", v + 1);
        }
    }

    public async Task SaveAsync(AnalysisResult r, CancellationToken cancellationToken)
    {
        await using var c = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = (SqliteTransaction)await c.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        var id = r.AnalysisId.ToString("N");
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        await c.ExecuteAsync("""
            INSERT INTO samples(sha256, file_name, size, kind, first_seen, last_seen, times_analyzed)
            VALUES (@Sha256, @FileName, @Size, @Kind, @Now, @Now, 1)
            ON CONFLICT(sha256) DO UPDATE SET last_seen = @Now, times_analyzed = times_analyzed + 1, file_name = @FileName
            """, new { r.Sample.Sha256, r.Sample.FileName, r.Sample.Size, Kind = r.Sample.Kind.ToString(), Now = now }, tx).ConfigureAwait(false);

        // Re-saving an analysis replaces it completely.
        await DeleteRowsAsync(c, tx, id).ConfigureAwait(false);

        await c.ExecuteAsync("""
            INSERT INTO analyses(id, sha256, file_name, kind, started_at, completed_at, stage, score, verdict, provider, is_demo,
                                 event_count, finding_count, failure_reason, monitoring_interrupted, suppressed_noise, options_json)
            VALUES (@Id, @Sha256, @FileName, @Kind, @StartedAt, @CompletedAt, @Stage, @Score, @Verdict, @Provider, @IsDemo,
                    @EventCount, @FindingCount, @FailureReason, @Interrupted, @Suppressed, @Options)
            """, new
        {
            Id = id,
            r.Sample.Sha256,
            r.Sample.FileName,
            Kind = r.Sample.Kind.ToString(),
            StartedAt = r.StartedAt.ToUnixTimeMilliseconds(),
            CompletedAt = r.CompletedAt?.ToUnixTimeMilliseconds(),
            Stage = r.FinalStage.ToString(),
            r.Risk.Score,
            Verdict = r.Risk.Verdict.ToString(),
            Provider = r.ProviderId,
            IsDemo = r.IsDemo ? 1 : 0,
            EventCount = r.Events.Count,
            FindingCount = r.Findings.Count,
            r.FailureReason,
            Interrupted = r.MonitoringInterrupted ? 1 : 0,
            Suppressed = r.SuppressedNoiseEvents,
            Options = JsonSerializer.Serialize(r.Options, BlazmaJson.Options),
        }, tx).ConfigureAwait(false);

        await InsertEventsAsync(c, tx, id, r.Events, cancellationToken).ConfigureAwait(false);

        foreach (var p in r.AllProcesses)
        {
            await c.ExecuteAsync("""
                INSERT OR REPLACE INTO processes(analysis_id, pkey, pid, parent_key, name, image, command_line, start_ticks, end_ticks, in_tree, is_sample)
                VALUES (@Id, @Key, @Pid, @Parent, @Name, @Image, @Cmd, @Start, @End, @InTree, @IsSample)
                """, new
            {
                Id = id, Key = p.Key.ToString(), p.Pid, Parent = p.ParentKey?.ToString(), p.Name, Image = p.ImagePath, Cmd = p.CommandLine,
                Start = p.Start.Ticks, End = p.End?.Ticks, InTree = p.InAnalyzedTree ? 1 : 0, IsSample = p.IsSample ? 1 : 0,
            }, tx).ConfigureAwait(false);
        }

        foreach (var f in r.Findings)
        {
            await c.ExecuteAsync("""
                INSERT OR REPLACE INTO findings(analysis_id, id, rule_id, category, severity, points, title_en, title_ar)
                VALUES (@Id, @FId, @RuleId, @Category, @Severity, @Points, @TitleEn, @TitleAr)
                """, new { Id = id, FId = f.Id, f.RuleId, Category = f.Category.ToString(), Severity = (int)f.Severity, f.Points, TitleEn = f.Title.En, TitleAr = f.Title.Ar }, tx).ConfigureAwait(false);
        }

        foreach (var i in r.Indicators)
        {
            await c.ExecuteAsync("""
                INSERT OR REPLACE INTO indicators(analysis_id, type, value, status, source)
                VALUES (@Id, @Type, @Value, @Status, @Source)
                """, new { Id = id, Type = i.Type.ToString(), i.Value, Status = i.Status.ToString(), i.Source }, tx).ConfigureAwait(false);
        }

        var document = new ReportDocument
        {
            Static = r.Static,
            ProcessRoots = r.ProcessRoots.ToList(),
            Findings = r.Findings.ToList(),
            Risk = r.Risk,
            Chains = r.Chains.ToList(),
            Persistence = r.Persistence.ToList(),
            Indicators = r.Indicators.ToList(),
            SystemChanges = r.SystemChanges,
        };
        await c.ExecuteAsync("INSERT INTO report_documents(analysis_id, schema_version, document) VALUES (@Id, @V, @Doc)",
            new { Id = id, V = AnalysisResult.SchemaVersion, Doc = Compress(JsonSerializer.SerializeToUtf8Bytes(document, BlazmaJson.Options)) }, tx).ConfigureAwait(false);

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task InsertEventsAsync(SqliteConnection c, SqliteTransaction tx, string id, IReadOnlyList<AnalysisEvent> events, CancellationToken ct)
    {
        await using var insert = c.CreateCommand();
        insert.Transaction = tx;
        insert.CommandText = """
            INSERT INTO events(analysis_id, seq, ts, rel_ticks, category, action, pid, ppid, pkey, process, target, details, severity, source, correlation)
            VALUES ($a, $seq, $ts, $rel, $cat, $act, $pid, $ppid, $pkey, $proc, $tgt, $det, $sev, $src, $cor)
            """;
        var names = new[] { "$a", "$seq", "$ts", "$rel", "$cat", "$act", "$pid", "$ppid", "$pkey", "$proc", "$tgt", "$det", "$sev", "$src", "$cor" };
        var ps = names.Select(n => insert.Parameters.Add(n, SqliteType.Text)).ToArray();

        await using var fts = c.CreateCommand();
        fts.Transaction = tx;
        fts.CommandText = "INSERT INTO events_fts(analysis_id, seq, category, process, target, details) VALUES ($a, $seq, $cat, $proc, $tgt, $det)";
        var fa = fts.Parameters.Add("$a", SqliteType.Text);
        var fseq = fts.Parameters.Add("$seq", SqliteType.Integer);
        var fcat = fts.Parameters.Add("$cat", SqliteType.Integer);
        var fproc = fts.Parameters.Add("$proc", SqliteType.Text);
        var ftgt = fts.Parameters.Add("$tgt", SqliteType.Text);
        var fdet = fts.Parameters.Add("$det", SqliteType.Text);

        insert.Prepare();
        fts.Prepare();
        foreach (var e in events)
        {
            ct.ThrowIfCancellationRequested();
            var details = e.Details.Count == 0 ? null : JsonSerializer.Serialize(e.Details, BlazmaJson.Options);
            ps[0].Value = id;
            ps[1].Value = e.Sequence;
            ps[2].Value = e.Timestamp.ToUnixTimeMilliseconds();
            ps[3].Value = e.RelativeTime.Ticks;
            ps[4].Value = (int)e.Category;
            ps[5].Value = (int)e.Action;
            ps[6].Value = e.ProcessId;
            ps[7].Value = e.ParentProcessId;
            ps[8].Value = (object?)e.Process?.ToString() ?? DBNull.Value;
            ps[9].Value = e.ProcessName;
            ps[10].Value = (object?)e.Target ?? DBNull.Value;
            ps[11].Value = (object?)details ?? DBNull.Value;
            ps[12].Value = (int)e.Severity;
            ps[13].Value = e.Source;
            ps[14].Value = (object?)e.CorrelationId ?? DBNull.Value;
            await insert.ExecuteNonQueryAsync(ct).ConfigureAwait(false);

            fa.Value = id;
            fseq.Value = e.Sequence;
            fcat.Value = (int)e.Category;
            fproc.Value = e.ProcessName;
            ftgt.Value = (object?)e.Target ?? DBNull.Value;
            fdet.Value = (object?)(details is null ? null : string.Join(' ', e.Details.Values)) ?? DBNull.Value;
            await fts.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
    }

    public async Task<AnalysisResult?> LoadAsync(Guid id, bool includeEvents, CancellationToken cancellationToken)
    {
        await using var c = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var key = id.ToString("N");
        var row = await c.QuerySingleOrDefaultAsync<AnalysisRow>("""
            SELECT a.id AS Id, a.sha256 AS Sha256, a.file_name AS FileName, a.kind AS Kind, a.started_at AS StartedAt, a.completed_at AS CompletedAt,
                   a.stage AS Stage, a.score AS Score, a.verdict AS Verdict, a.provider AS Provider, a.is_demo AS IsDemo, a.event_count AS EventCount,
                   a.finding_count AS FindingCount, a.failure_reason AS FailureReason, a.monitoring_interrupted AS MonitoringInterrupted,
                   a.suppressed_noise AS SuppressedNoise, a.options_json AS OptionsJson, s.size AS Size
            FROM analyses a JOIN samples s ON s.sha256 = a.sha256 WHERE a.id = @key
            """, new { key }).ConfigureAwait(false);
        if (row is null) return null;

        var blob = await c.ExecuteScalarAsync<byte[]?>("SELECT document FROM report_documents WHERE analysis_id = @key", new { key }).ConfigureAwait(false);
        var doc = blob is null ? new ReportDocument() : JsonSerializer.Deserialize<ReportDocument>(Decompress(blob), BlazmaJson.Options) ?? new ReportDocument();

        var sample = doc.Static?.Sample ?? new SampleInfo
        {
            FileName = row.FileName,
            Size = row.Size,
            Sha256 = row.Sha256,
            Sha1 = string.Empty,
            Kind = Enum.TryParse<FileKind>(row.Kind, out var k) ? k : FileKind.Unknown,
        };

        var result = new AnalysisResult
        {
            AnalysisId = id,
            Sample = sample,
            Static = doc.Static,
            Options = JsonSerializer.Deserialize<AnalysisOptions>(row.OptionsJson, BlazmaJson.Options) ?? new AnalysisOptions(),
            ProviderId = row.Provider,
            IsDemo = row.IsDemo != 0,
            StartedAt = DateTimeOffset.FromUnixTimeMilliseconds(row.StartedAt),
            CompletedAt = row.CompletedAt is { } ca ? DateTimeOffset.FromUnixTimeMilliseconds(ca) : null,
            FinalStage = Enum.TryParse<AnalysisStage>(row.Stage, out var st) ? st : AnalysisStage.Failed,
            FailureReason = row.FailureReason,
            ProcessRoots = doc.ProcessRoots,
            Findings = doc.Findings,
            Risk = doc.Risk,
            Chains = doc.Chains,
            Persistence = doc.Persistence,
            Indicators = doc.Indicators,
            SystemChanges = doc.SystemChanges,
            MonitoringInterrupted = row.MonitoringInterrupted != 0,
            SuppressedNoiseEvents = (int)row.SuppressedNoise,
        };
        if (includeEvents)
            result.Events = await QueryEventsAsync(new EventQuery { AnalysisId = id, Limit = int.MaxValue }, cancellationToken).ConfigureAwait(false);
        return result;
    }

    public async Task<IReadOnlyList<AnalysisSummary>> ListAsync(int limit, int offset, CancellationToken cancellationToken)
    {
        await using var c = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var rows = await c.QueryAsync<AnalysisRow>("""
            SELECT a.id AS Id, a.sha256 AS Sha256, a.file_name AS FileName, a.kind AS Kind, a.started_at AS StartedAt, a.completed_at AS CompletedAt,
                   a.stage AS Stage, a.score AS Score, a.verdict AS Verdict, a.provider AS Provider, a.is_demo AS IsDemo,
                   a.event_count AS EventCount, a.finding_count AS FindingCount, a.options_json AS OptionsJson
            FROM analyses a ORDER BY a.started_at DESC LIMIT @limit OFFSET @offset
            """, new { limit, offset }).ConfigureAwait(false);
        return rows.Select(ToSummary).ToList();
    }

    public async Task<IReadOnlyList<AnalysisEvent>> QueryEventsAsync(EventQuery q, CancellationToken cancellationToken)
    {
        await using var c = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var (where, args) = BuildEventFilter(q);
        args.Add("limit", q.Limit);
        args.Add("offset", q.Offset);
        var rows = await c.QueryAsync<EventRow>($"""
            SELECT seq AS Seq, ts AS Ts, rel_ticks AS RelTicks, category AS Category, action AS Action, pid AS Pid, ppid AS Ppid,
                   pkey AS PKey, process AS Process, target AS Target, details AS Details, severity AS Severity, source AS Source, correlation AS Correlation
            FROM events WHERE {where} ORDER BY rel_ticks, seq LIMIT @limit OFFSET @offset
            """, args).ConfigureAwait(false);
        return rows.Select(ToEvent).ToList();
    }

    public async Task<int> CountEventsAsync(EventQuery q, CancellationToken cancellationToken)
    {
        await using var c = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var (where, args) = BuildEventFilter(q);
        return await c.ExecuteScalarAsync<int>($"SELECT COUNT(*) FROM events WHERE {where}", args).ConfigureAwait(false);
    }

    private static (string Where, DynamicParameters Args) BuildEventFilter(EventQuery q)
    {
        var clauses = new List<string> { "analysis_id = @id" };
        var args = new DynamicParameters();
        args.Add("id", q.AnalysisId.ToString("N"));
        if (q.Categories is { Count: > 0 })
        {
            clauses.Add("category IN @cats");
            args.Add("cats", q.Categories.Select(x => (int)x).ToArray());
        }
        if (q.MinSeverity is { } sev) { clauses.Add("severity >= @sev"); args.Add("sev", (int)sev); }
        if (q.ProcessId is { } pid) { clauses.Add("pid = @pid"); args.Add("pid", pid); }
        if (q.From is { } from) { clauses.Add("rel_ticks >= @from"); args.Add("from", from.Ticks); }
        if (q.To is { } to) { clauses.Add("rel_ticks <= @to"); args.Add("to", to.Ticks); }
        if (!string.IsNullOrWhiteSpace(q.Text))
        {
            clauses.Add("(process LIKE @text ESCAPE '\\' OR target LIKE @text ESCAPE '\\' OR details LIKE @text ESCAPE '\\')");
            args.Add("text", "%" + EscapeLike(q.Text.Trim()) + "%");
        }
        return (string.Join(" AND ", clauses), args);
    }

    public async Task<IReadOnlyList<SearchHit>> SearchAsync(string text, int limit, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(text)) return [];
        await using var c = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var hits = new List<SearchHit>();
        var names = (await c.QueryAsync<(string Id, string FileName)>("SELECT id, file_name FROM analyses").ConfigureAwait(false))
            .ToDictionary(x => x.Id, x => x.FileName);

        var like = "%" + EscapeLike(text.Trim()) + "%";
        foreach (var a in await c.QueryAsync<(string Id, string FileName, string Sha256)>(
                     "SELECT id, file_name, sha256 FROM analyses WHERE file_name LIKE @like ESCAPE '\\' OR sha256 LIKE @like ESCAPE '\\' ORDER BY started_at DESC LIMIT 20", new { like }).ConfigureAwait(false))
            hits.Add(new SearchHit(Guid.ParseExact(a.Id, "N"), a.FileName, SearchSource.Finding, a.FileName, a.Sha256, null));

        foreach (var i in await c.QueryAsync<(string AnalysisId, string Type, string Value, string Status)>(
                     "SELECT analysis_id, type, value, status FROM indicators WHERE value LIKE @like ESCAPE '\\' LIMIT 50", new { like }).ConfigureAwait(false))
            hits.Add(new SearchHit(Guid.ParseExact(i.AnalysisId, "N"), names.GetValueOrDefault(i.AnalysisId, "?"), SearchSource.Indicator, $"{i.Type}: {i.Value}", i.Status, null));

        foreach (var f in await c.QueryAsync<(string AnalysisId, string RuleId, string TitleEn)>(
                     "SELECT analysis_id, rule_id, title_en FROM findings WHERE title_en LIKE @like ESCAPE '\\' OR title_ar LIKE @like ESCAPE '\\' OR rule_id LIKE @like ESCAPE '\\' LIMIT 30", new { like }).ConfigureAwait(false))
            hits.Add(new SearchHit(Guid.ParseExact(f.AnalysisId, "N"), names.GetValueOrDefault(f.AnalysisId, "?"), SearchSource.Finding, f.TitleEn, f.RuleId, null));

        var match = FtsQuery(text);
        if (match.Length > 0)
        {
            var rows = await c.QueryAsync<(string AnalysisId, long Seq, long Category, string Process, string? Target)>(
                "SELECT analysis_id, seq, category, process, target FROM events_fts WHERE events_fts MATCH @match ORDER BY rank LIMIT @limit",
                new { match, limit }).ConfigureAwait(false);
            foreach (var e in rows)
            {
                var source = (EventCategory)e.Category switch
                {
                    EventCategory.Process => SearchSource.Process,
                    EventCategory.File => SearchSource.File,
                    EventCategory.Registry => SearchSource.Registry,
                    EventCategory.Network or EventCategory.Dns => SearchSource.Network,
                    _ => SearchSource.Timeline,
                };
                hits.Add(new SearchHit(Guid.ParseExact(e.AnalysisId, "N"), names.GetValueOrDefault(e.AnalysisId, "?"), source, e.Process, e.Target ?? string.Empty, e.Seq));
            }
        }
        return hits.Take(limit).ToList();
    }

    /// <summary>User text becomes quoted prefix terms, so FTS syntax in the input is never interpreted.</summary>
    internal static string FtsQuery(string text)
    {
        var terms = text.Split([' ', '\t', '\\', '/', ':', '"', '\''], StringSplitOptions.RemoveEmptyEntries)
            .Select(t => new string(t.Where(ch => char.IsLetterOrDigit(ch) || ch is '.' or '_' or '-').ToArray()))
            .Where(t => t.Length > 0)
            .Take(8)
            .Select(t => "\"" + t + "\"*");
        return string.Join(' ', terms);
    }

    public async Task<DashboardStats> GetStatsAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using var c = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var startOfDay = new DateTimeOffset(now.Date, now.Offset).ToUnixTimeMilliseconds();
        var rows = (await c.QueryAsync<(string Verdict, long StartedAt, string Stage)>("SELECT verdict, started_at, stage FROM analyses").ConfigureAwait(false)).ToList();
        var completed = rows.Where(r => r.Stage == nameof(AnalysisStage.Completed)).ToList();
        return new DashboardStats(
            rows.Count(r => r.StartedAt >= startOfDay),
            completed.Count(r => r.Verdict is nameof(Verdict.HighRiskBehavior) or nameof(Verdict.CriticalBehavior)),
            completed.Count(r => r.Verdict == nameof(Verdict.Suspicious)),
            completed.Count(r => r.Verdict == nameof(Verdict.LowRisk)),
            rows.Count);
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken)
    {
        await using var c = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = (SqliteTransaction)await c.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await DeleteRowsAsync(c, tx, id.ToString("N")).ConfigureAwait(false);
        await c.ExecuteAsync("DELETE FROM samples WHERE sha256 NOT IN (SELECT sha256 FROM analyses)", transaction: tx).ConfigureAwait(false);
        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<int> PurgeOlderThanAsync(DateTimeOffset cutoff, CancellationToken cancellationToken)
    {
        await using var c = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var ids = (await c.QueryAsync<string>("SELECT id FROM analyses WHERE started_at < @t", new { t = cutoff.ToUnixTimeMilliseconds() }).ConfigureAwait(false)).ToList();
        foreach (var id in ids) await DeleteAsync(Guid.ParseExact(id, "N"), cancellationToken).ConfigureAwait(false);
        return ids.Count;
    }

    private static async Task DeleteRowsAsync(SqliteConnection c, SqliteTransaction tx, string id)
    {
        foreach (var table in new[] { "events", "events_fts", "processes", "findings", "indicators", "report_documents" })
            await c.ExecuteAsync($"DELETE FROM {table} WHERE analysis_id = @id", new { id }, tx).ConfigureAwait(false);
        await c.ExecuteAsync("DELETE FROM analyses WHERE id = @id", new { id }, tx).ConfigureAwait(false);
    }

    private static string EscapeLike(string s) => s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal);

    private static byte[] Compress(byte[] data)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Optimal)) gzip.Write(data);
        return output.ToArray();
    }

    private static byte[] Decompress(byte[] data)
    {
        using var input = new GZipStream(new MemoryStream(data), CompressionMode.Decompress);
        using var output = new MemoryStream();
        input.CopyTo(output);
        return output.ToArray();
    }

    private static AnalysisSummary ToSummary(AnalysisRow r) => new()
    {
        Id = Guid.ParseExact(r.Id, "N"),
        FileName = r.FileName,
        Sha256 = r.Sha256,
        Kind = Enum.TryParse<FileKind>(r.Kind, out var k) ? k : FileKind.Unknown,
        StartedAt = DateTimeOffset.FromUnixTimeMilliseconds(r.StartedAt),
        CompletedAt = r.CompletedAt is { } c ? DateTimeOffset.FromUnixTimeMilliseconds(c) : null,
        Stage = Enum.TryParse<AnalysisStage>(r.Stage, out var s) ? s : AnalysisStage.Failed,
        Score = (int)r.Score,
        Verdict = Enum.TryParse<Verdict>(r.Verdict, out var v) ? v : Verdict.LowRisk,
        ProviderId = r.Provider,
        IsDemo = r.IsDemo != 0,
        EventCount = (int)r.EventCount,
        FindingCount = (int)r.FindingCount,
    };

    private static AnalysisEvent ToEvent(EventRow r) => new()
    {
        Sequence = r.Seq,
        Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(r.Ts),
        RelativeTime = TimeSpan.FromTicks(r.RelTicks),
        Category = (EventCategory)r.Category,
        Action = (EventAction)r.Action,
        ProcessId = (int)r.Pid,
        ParentProcessId = (int)r.Ppid,
        Process = ProcessKey.TryParse(r.PKey, out var key) ? key : null,
        ProcessName = r.Process,
        Target = r.Target,
        Details = r.Details is null ? new Dictionary<string, string>() : JsonSerializer.Deserialize<Dictionary<string, string>>(r.Details, BlazmaJson.Options) ?? [],
        Severity = (Severity)r.Severity,
        Source = r.Source,
        CorrelationId = r.Correlation,
    };

    private sealed class AnalysisRow
    {
        public string Id { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public string FileName { get; set; } = "";
        public string Kind { get; set; } = "";
        public long StartedAt { get; set; }
        public long? CompletedAt { get; set; }
        public string Stage { get; set; } = "";
        public long Score { get; set; }
        public string Verdict { get; set; } = "";
        public string Provider { get; set; } = "";
        public long IsDemo { get; set; }
        public long EventCount { get; set; }
        public long FindingCount { get; set; }
        public string? FailureReason { get; set; }
        public long MonitoringInterrupted { get; set; }
        public long SuppressedNoise { get; set; }
        public string OptionsJson { get; set; } = "{}";
        public long Size { get; set; }
    }

    private sealed class EventRow
    {
        public long Seq { get; set; }
        public long Ts { get; set; }
        public long RelTicks { get; set; }
        public long Category { get; set; }
        public long Action { get; set; }
        public long Pid { get; set; }
        public long Ppid { get; set; }
        public string? PKey { get; set; }
        public string Process { get; set; } = "";
        public string? Target { get; set; }
        public string? Details { get; set; }
        public long Severity { get; set; }
        public string Source { get; set; } = "";
        public string? Correlation { get; set; }
    }
}
