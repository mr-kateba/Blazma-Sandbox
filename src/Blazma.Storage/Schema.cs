namespace Blazma.Storage;

/// <summary>
/// Versioned schema. Each migration runs once, in order, inside a transaction.
///
/// Design notes:
/// <list type="bullet">
/// <item>All observed activity lives in one <c>events</c> table (the unified event model).
/// File, registry and network activity are views over it by category, indexed so each tab
/// pages quickly through 100k+ events.</item>
/// <item>Derived results (findings, chains, process tree, risk, snapshot diff) are stored as
/// one compressed document per analysis, and the parts that are searched or listed
/// (findings, indicators, processes) are also stored as rows.</item>
/// </list>
/// </summary>
internal static class Schema
{
    public static readonly string[] Migrations =
    [
        """
        CREATE TABLE samples (
            sha256 TEXT PRIMARY KEY,
            file_name TEXT NOT NULL,
            size INTEGER NOT NULL,
            kind TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            times_analyzed INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE analyses (
            id TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL REFERENCES samples(sha256),
            file_name TEXT NOT NULL,
            kind TEXT NOT NULL,
            started_at INTEGER NOT NULL,
            completed_at INTEGER,
            stage TEXT NOT NULL,
            score INTEGER NOT NULL DEFAULT 0,
            verdict TEXT NOT NULL,
            provider TEXT NOT NULL,
            is_demo INTEGER NOT NULL DEFAULT 0,
            event_count INTEGER NOT NULL DEFAULT 0,
            finding_count INTEGER NOT NULL DEFAULT 0,
            failure_reason TEXT,
            monitoring_interrupted INTEGER NOT NULL DEFAULT 0,
            suppressed_noise INTEGER NOT NULL DEFAULT 0,
            options_json TEXT NOT NULL
        );
        CREATE INDEX ix_analyses_started ON analyses(started_at DESC);
        CREATE INDEX ix_analyses_sha256 ON analyses(sha256);
        CREATE INDEX ix_analyses_verdict ON analyses(verdict, started_at);

        CREATE TABLE events (
            analysis_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            rel_ticks INTEGER NOT NULL,
            category INTEGER NOT NULL,
            action INTEGER NOT NULL,
            pid INTEGER NOT NULL,
            ppid INTEGER NOT NULL,
            pkey TEXT,
            process TEXT NOT NULL,
            target TEXT,
            details TEXT,
            severity INTEGER NOT NULL,
            source TEXT NOT NULL,
            correlation TEXT,
            PRIMARY KEY (analysis_id, seq)
        ) WITHOUT ROWID;
        CREATE INDEX ix_events_time ON events(analysis_id, rel_ticks, seq);
        CREATE INDEX ix_events_category ON events(analysis_id, category, rel_ticks);
        CREATE INDEX ix_events_pid ON events(analysis_id, pid);

        CREATE VIRTUAL TABLE events_fts USING fts5(
            analysis_id UNINDEXED, seq UNINDEXED, category UNINDEXED,
            process, target, details,
            tokenize = 'unicode61 remove_diacritics 2 tokenchars ''._-'''
        );

        CREATE TABLE processes (
            analysis_id TEXT NOT NULL,
            pkey TEXT NOT NULL,
            pid INTEGER NOT NULL,
            parent_key TEXT,
            name TEXT NOT NULL,
            image TEXT,
            command_line TEXT,
            start_ticks INTEGER NOT NULL,
            end_ticks INTEGER,
            in_tree INTEGER NOT NULL,
            is_sample INTEGER NOT NULL,
            PRIMARY KEY (analysis_id, pkey)
        ) WITHOUT ROWID;
        CREATE INDEX ix_processes_name ON processes(name);

        CREATE TABLE findings (
            analysis_id TEXT NOT NULL,
            id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            category TEXT NOT NULL,
            severity INTEGER NOT NULL,
            points INTEGER NOT NULL,
            title_en TEXT NOT NULL,
            title_ar TEXT NOT NULL,
            PRIMARY KEY (analysis_id, id)
        ) WITHOUT ROWID;
        CREATE INDEX ix_findings_rule ON findings(rule_id);

        CREATE TABLE indicators (
            analysis_id TEXT NOT NULL,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            status TEXT NOT NULL,
            source TEXT NOT NULL,
            PRIMARY KEY (analysis_id, type, value)
        ) WITHOUT ROWID;
        CREATE INDEX ix_indicators_value ON indicators(value COLLATE NOCASE);

        CREATE TABLE report_documents (
            analysis_id TEXT PRIMARY KEY,
            schema_version INTEGER NOT NULL,
            document BLOB NOT NULL
        );
        """,
    ];
}
