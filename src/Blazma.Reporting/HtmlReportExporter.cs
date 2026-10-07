using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Indicators;
using Blazma.Core.Processes;
using Engine = Blazma.Analysis.Engine;
using Blazma.Storage;

namespace Blazma.Reporting;

/// <summary>
/// A single-file HTML report that opens in any browser without Blazma. No scripts, no
/// external resources; a Content-Security-Policy blocks both. Every value that came from
/// the sample (paths, command lines, domains) is HTML-encoded.
/// </summary>
public sealed class HtmlReportExporter : IReportExporter
{
    private readonly Func<bool, Redactor> _redactorFactory;

    public HtmlReportExporter(Func<bool, Redactor>? redactorFactory = null)
    {
        _redactorFactory = redactorFactory ?? (redact => redact ? new Redactor() : Redactor.None);
    }

    public string Format => "HTML";
    public string FileExtension => ".html";

    public async Task ExportAsync(AnalysisResult result, Stream destination, ExportOptions options, CancellationToken cancellationToken)
    {
        var html = Render(result, options, _redactorFactory(options.Redact));
        await destination.WriteAsync(Encoding.UTF8.GetBytes(html), cancellationToken).ConfigureAwait(false);
    }

    internal static string Render(AnalysisResult a, ExportOptions o, Redactor r)
    {
        var t = ReportStrings.For(o.Language);
        var lang = t.Lang;
        string E(string? s) => WebUtility.HtmlEncode(r.Apply(s) ?? string.Empty);
        string L(Core.Text.LocalizedText text) => E(text.Get(lang));

        var contentHash = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(JsonReportExporter.BuildContent(a, o, r), BlazmaJson.Options)));
        var sb = new StringBuilder(64 * 1024);
        sb.Append($"""
            <!doctype html>
            <html lang="{lang}" dir="{(t.Rtl ? "rtl" : "ltr")}">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
            <meta name="referrer" content="no-referrer">
            <title>{E(a.Sample.FileName)} · Blazma Sandbox</title>
            <style>{Css}</style>
            </head>
            <body>
            <main>
            <header class="top">
              <div class="brand">{LogoSvg}<div><b>BLAZMA</b><small>SANDBOX</small></div></div>
              <div class="meta">{E(t.Title)} · {E(a.StartedAt.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture))} UTC</div>
            </header>
            """);

        if (a.IsDemo) sb.Append($"<div class=\"banner demo\">{E(t.Demo)}</div>");
        if (a.MonitoringInterrupted) sb.Append($"<div class=\"banner warn\">{E(t.Interrupted)}</div>");

        // Overview: big score + file info
        var verdictClass = a.Risk.Verdict switch
        {
            Verdict.CriticalBehavior => "crit",
            Verdict.HighRiskBehavior => "high",
            Verdict.Suspicious => "med",
            _ => "low",
        };
        sb.Append($"""
            <section class="overview">
              <div class="score {verdictClass}">
                <div class="num">{a.Risk.Score}</div><div class="of">/ 100</div>
                <div class="verdict">{Icon(verdictClass)} {E(VerdictText.Of(a.Risk.Verdict, lang))}</div>
              </div>
              <div class="file">
                <h1 class="ltr">{E(a.Sample.FileName)}</h1>
                <dl>
                  <dt>SHA-256</dt><dd class="mono">{E(a.Sample.Sha256)}</dd>
                  <dt>{E(t.Size)}</dt><dd>{a.Sample.Size.ToString("N0", CultureInfo.InvariantCulture)} B</dd>
                  <dt>{E(t.Type)}</dt><dd>{E(a.Sample.Kind.ToString())}{(a.Static?.Pe is { } pe ? $" · {E(pe.Machine)}" : string.Empty)}</dd>
                  <dt>{E(t.Signature)}</dt><dd>{E(a.Static?.Signature.Status.ToString() ?? "-")}{(a.Static?.Signature.Publisher is { } pub ? " · " + E(pub) : string.Empty)}</dd>
                  <dt>{E(t.Duration)}</dt><dd>{(a.Duration is { } d ? d.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) + " s" : "-")}</dd>
                  <dt>{E(t.Provider)}</dt><dd>{E(a.ProviderId)}</dd>
                </dl>
              </div>
            </section>
            <p class="disclaimer">{E(t.Rtl ? RiskAssessment.DisclaimerAr : RiskAssessment.Disclaimer)}</p>
            """);

        // Why this score
        sb.Append($"<section><h2>{E(t.WhyScore)}</h2>");
        if (a.Risk.Contributions.Count == 0) sb.Append($"<p class=\"muted\">{E(t.NoFindings)}</p>");
        else
        {
            sb.Append("<ul class=\"why\">");
            foreach (var c in a.Risk.Contributions)
                sb.Append($"<li><span class=\"pts\">+{c.Points}</span> {L(c.Title)}{(c.Capped ? " <span class=\"muted\">(capped)</span>" : string.Empty)}</li>");
            sb.Append("</ul>");
        }
        sb.Append("</section>");

        // Findings
        sb.Append($"<section><h2>{E(t.ImportantFindings)}</h2>");
        if (a.Findings.Count == 0) sb.Append($"<p class=\"muted\">{E(t.NoFindings)}</p>");
        foreach (var f in a.Findings)
        {
            var sev = SevClass(f.Severity);
            sb.Append($"""
                <article class="finding {sev}">
                  <div class="fhead"><span class="badge {sev}">{Icon(sev)} {E(VerdictText.Of(f.Severity, lang))}</span><h3>{L(f.Title)}</h3><span class="rule mono">{E(f.RuleId)}{(f.AttackTechniques.Count > 0 ? " · ATT&amp;CK " + E(string.Join(", ", f.AttackTechniques)) : string.Empty)}</span></div>
                  <p>{L(f.Explanation)}</p>
                  <details><summary>{E(t.Evidence)} ({f.Evidence.Count})</summary><ul>
                """);
            foreach (var ev in f.Evidence)
                sb.Append($"<li>{L(ev.Description)}{(ev.Technical is null ? string.Empty : $"<pre>{E(ev.Technical)}</pre>")}</li>");
            sb.Append("</ul></details></article>");
        }
        sb.Append("</section>");

        // Chains
        if (a.Chains.Count > 0)
        {
            sb.Append($"<section><h2>{E(t.BehaviorChains)}</h2>");
            foreach (var c in a.Chains)
            {
                sb.Append($"<div class=\"chain {SevClass(c.Severity)}\"><h3>{L(c.Title)}</h3><ol>");
                foreach (var s in c.Steps)
                    sb.Append($"<li><span class=\"step\">{E(s.Kind.ToString())}</span> <span class=\"ltr\">{E(s.Target)}</span> <span class=\"muted mono\">{Ms(s.Time)}</span></li>");
                sb.Append("</ol></div>");
            }
            sb.Append("</section>");
        }

        // Process tree
        sb.Append($"<section><h2>{E(t.ProcessTree)}</h2>");
        var roots = a.ProcessRoots.Where(n => n.SelfAndDescendants().Any(x => x.InAnalyzedTree)).ToList();
        if (roots.Count == 0) roots = a.ProcessRoots.ToList();
        if (roots.Count == 0) sb.Append($"<p class=\"muted\">{E(t.Nothing)}</p>");
        else
        {
            sb.Append("<ul class=\"tree\">");
            foreach (var root in roots) Tree(sb, root, E);
            sb.Append("</ul>");
        }
        sb.Append("</section>");

        // Network
        var dns = a.Events.Where(e => e.Action == EventAction.DnsQuery).GroupBy(e => e.Detail(DetailKeys.QueryName) ?? e.Target ?? "?").Take(100).ToList();
        var conns = a.Events.Where(e => e.Action == EventAction.NetworkConnect).Take(200).ToList();
        sb.Append($"<section><h2>{E(t.Network)}</h2>");
        if (dns.Count == 0 && conns.Count == 0) sb.Append($"<p class=\"muted\">{E(t.Nothing)}</p>");
        if (dns.Count > 0)
        {
            sb.Append($"<h3>{E(t.Dns)}</h3><table><tr><th>{E(t.Time)}</th><th>{E(t.Process)}</th><th>Domain</th><th>Result</th></tr>");
            foreach (var g in dns)
            {
                var e = g.First();
                sb.Append($"<tr><td class=\"mono\">{Ms(e.RelativeTime)}</td><td>{E(e.ProcessName)}</td><td class=\"ltr\">{E(g.Key)}</td><td class=\"mono\">{E(e.Detail(DetailKeys.QueryResult) ?? "-")}</td></tr>");
            }
            sb.Append("</table>");
        }
        if (conns.Count > 0)
        {
            sb.Append($"<h3>{E(t.Connections)}</h3><table><tr><th>{E(t.Time)}</th><th>{E(t.Process)}</th><th>IP</th><th>Port</th><th>Protocol</th></tr>");
            foreach (var e in conns)
                sb.Append($"<tr><td class=\"mono\">{Ms(e.RelativeTime)}</td><td>{E(e.ProcessName)}</td><td class=\"mono\">{E(e.Detail(DetailKeys.RemoteAddress) ?? e.Target)}</td><td class=\"mono\">{E(e.Detail(DetailKeys.RemotePort))}</td><td>{E(e.Detail(DetailKeys.Protocol) ?? "TCP")}</td></tr>");
            sb.Append("</table>");
        }
        sb.Append("</section>");

        // Persistence
        sb.Append($"<section><h2>{E(t.Persistence)}</h2>");
        if (a.Persistence.Count == 0) sb.Append($"<p class=\"muted\">{E(t.Nothing)}</p>");
        foreach (var p in a.Persistence)
        {
            var sev = SevClass(p.Severity);
            sb.Append($"""
                <article class="finding {sev}">
                  <div class="fhead"><span class="badge {sev}">{Icon(sev)} {E(VerdictText.Of(p.Severity, lang))}</span><h3>{L(Engine.PersistenceNames.Of(p.Technique))}</h3><span class="muted mono">{Ms(p.Time)}</span></div>
                  <p>{L(p.Explanation)}</p>
                  <pre>{E(p.Target)}{(p.Value is null ? string.Empty : "\n= " + E(p.Value))}</pre>
                  <p class="muted">{E(t.Process)}: {E(p.ProcessName)}</p>
                </article>
                """);
        }
        sb.Append("</section>");

        // System changes
        if (a.SystemChanges is { } sc)
        {
            sb.Append($"""
                <section><h2>{E(t.SystemChanges)}</h2>
                <div class="grid">
                  <div class="tile"><h4>{E(t.Files)}</h4><p>+{sc.FilesCreated.Count} {E(t.Created)}</p><p>~{sc.FilesModified.Count} {E(t.Modified)}</p><p>−{sc.FilesDeleted.Count} {E(t.Deleted)}</p></div>
                  <div class="tile"><h4>{E(t.Registry)}</h4><p>+{sc.RegistryAdded.Count} {E(t.Added)}</p><p>~{sc.RegistryModified.Count} {E(t.Modified)}</p><p>−{sc.RegistryRemoved.Count} {E(t.Removed)}</p></div>
                  <div class="tile"><h4>{E(t.Services)}</h4><p>+{sc.ServicesAdded.Count}</p></div>
                  <div class="tile"><h4>{E(t.Tasks)}</h4><p>+{sc.TasksAdded.Count}</p></div>
                  <div class="tile"><h4>{E(t.Startup)}</h4><p>+{sc.StartupAdded.Count}</p></div>
                </div>
                <details><summary>{E(t.Files)}</summary><pre>{E(string.Join("\n", sc.FilesCreated.Select(f => "+ " + f.Path).Concat(sc.FilesModified.Select(f => "~ " + f.Path)).Concat(sc.FilesDeleted.Select(f => "- " + f.Path)).Take(500)))}</pre></details>
                <details><summary>{E(t.Registry)}</summary><pre>{E(string.Join("\n", sc.RegistryAdded.Select(x => $"+ {x.Key}\\{x.ValueName} = {x.NewData}").Concat(sc.RegistryModified.Select(x => $"~ {x.Key}\\{x.ValueName}: {x.OldData} -> {x.NewData}")).Concat(sc.RegistryRemoved.Select(x => $"- {x.Key}\\{x.ValueName}")).Take(500)))}</pre></details>
                </section>
                """);
        }

        // Indicators
        if (o.IncludeIndicators)
        {
            sb.Append($"<section><h2>{E(t.Indicators)}</h2><table><tr><th>{E(t.Type)}</th><th>{E(t.Value)}</th><th>{E(t.Status)}</th></tr>");
            foreach (var i in a.Indicators)
                sb.Append($"<tr><td>{E(i.Type.ToString())}</td><td class=\"mono ltr\">{E(i.Value)}</td><td><span class=\"badge {IndicatorClass(i.Status)}\">{E(i.Status.ToString())}</span></td></tr>");
            sb.Append("</table></section>");
        }

        // Timeline summary
        if (o.IncludeTimeline)
        {
            var summary = JsonReportExporter.TimelineSummary(a, o.TimelineLimit);
            sb.Append($"<section><h2>{E(t.TimelineSummary)}</h2><p class=\"muted\">{E(string.Format(CultureInfo.InvariantCulture, t.ShownOf, summary.Count, a.Events.Count))}</p>");
            sb.Append($"<table><tr><th>{E(t.Time)}</th><th>{E(t.Action)}</th><th>{E(t.Process)}</th><th>{E(t.Target)}</th></tr>");
            foreach (var e in summary)
                sb.Append($"<tr class=\"{SevClass(e.Severity)}\"><td class=\"mono\">{Ms(e.RelativeTime)}</td><td>{E(e.Action.ToString())}</td><td>{E(e.ProcessName)}</td><td class=\"ltr\">{E(e.Target)}</td></tr>");
            sb.Append("</table></section>");
        }

        // Static
        if (o.IncludeStatic && a.Static?.Pe is { } spe)
        {
            sb.Append($"""
                <section><h2>{E(t.StaticDetails)}</h2>
                <dl class="cols">
                  <dt>{E(t.CompileTime)}</dt><dd>{E(spe.CompileTimestamp?.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) ?? "-")} <span class="muted">({E(t.CompileTimeNote)})</span></dd>
                  <dt>Subsystem</dt><dd>{E(spe.Subsystem)}</dd>
                  <dt>.NET</dt><dd>{(spe.IsDotNet ? "yes" : "no")}</dd>
                  <dt>Entropy</dt><dd>{a.Static.Entropy.ToString("0.00", CultureInfo.InvariantCulture)}</dd>
                </dl>
                <h3>{E(t.Sections)}</h3><table><tr><th>{E(t.Name)}</th><th>Virtual</th><th>Raw</th><th>Entropy</th></tr>
                """);
            foreach (var s in spe.Sections)
                sb.Append($"<tr><td class=\"mono\">{E(s.Name)}</td><td class=\"mono\">{s.VirtualSize}</td><td class=\"mono\">{s.RawSize}</td><td class=\"mono\">{s.Entropy.ToString("0.00", CultureInfo.InvariantCulture)}</td></tr>");
            sb.Append("</table>");
            if (spe.VersionInfo.Count > 0)
            {
                sb.Append("<dl class=\"cols\">");
                foreach (var (k, v) in spe.VersionInfo) sb.Append($"<dt>{E(k)}</dt><dd>{E(v)}</dd>");
                sb.Append("</dl>");
            }
            sb.Append("</section>");
        }

        sb.Append($"""
            <footer>
              <p>{E(t.LocalFirst)}</p>
              {(o.Redact ? $"<p>{E(t.Redacted)}</p>" : string.Empty)}
              <p class="mono">{E(t.Generated)}: {DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)} UTC · {E(t.Integrity)}: {contentHash}</p>
            </footer>
            </main>
            </body>
            </html>
            """);
        return sb.ToString();
    }

    private static void Tree(StringBuilder sb, ProcessNode n, Func<string?, string> e)
    {
        var tags = (n.IsSample ? " <span class=\"tag\">sample</span>" : string.Empty) + (n.ImageDroppedDuringAnalysis ? " <span class=\"tag warn\">dropped</span>" : string.Empty);
        sb.Append($"<li><span class=\"pname\">{e(n.Name)}</span> <span class=\"muted mono\">PID {n.Pid}</span>{tags}");
        if (!string.IsNullOrEmpty(n.CommandLine)) sb.Append($"<div class=\"cmd mono ltr\">{e(n.CommandLine)}</div>");
        if (n.Children.Count > 0)
        {
            sb.Append("<ul>");
            foreach (var c in n.Children) Tree(sb, c, e);
            sb.Append("</ul>");
        }
        sb.Append("</li>");
    }

    private static string Ms(TimeSpan t) => t < TimeSpan.Zero ? "-" : $"{(int)t.TotalMinutes:00}:{t.Seconds:00}.{t.Milliseconds:000}";

    private static string SevClass(Severity s) => s switch
    {
        Severity.Critical => "crit",
        Severity.High => "high",
        Severity.Medium => "med",
        Severity.Low => "low",
        _ => "info",
    };

    private static string IndicatorClass(IndicatorStatus s) => s switch
    {
        IndicatorStatus.HighRisk or IndicatorStatus.WatchlistMatch => "high",
        IndicatorStatus.Suspicious => "med",
        _ => "info",
    };

    /// <summary>Shapes as well as colours, so severity never depends on colour alone.</summary>
    private static string Icon(string cls) => cls switch
    {
        "crit" => "◆◆",
        "high" => "▲",
        "med" => "◆",
        "low" => "●",
        _ => "○",
    };

    private const string LogoSvg = """<svg viewBox="0 0 100 100" width="34" height="34" aria-hidden="true"><defs><linearGradient id="hx" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#FFB300"/><stop offset="1" stop-color="#FF3D00"/></linearGradient></defs><path d="M50,3 L91,26.5 L91,73.5 L50,97 L9,73.5 L9,26.5 Z" fill="url(#hx)"/><path d="M50,24 L72,36 L72,62 L50,74 L28,62 L28,36 Z M28,36 L50,48 L72,36 M50,48 L50,74" fill="none" stroke="#fff" stroke-width="6" stroke-linejoin="round" stroke-linecap="round"/></svg>""";

    private const string Css = """
        :root{--bg:#121216;--panel:#1c1c22;--field:#0d0d10;--rule:#2a2a33;--text:#f2f2f5;--muted:#a0a0ab;--accent:#ff6d00;--accent-text:#ff8a1f;--ok:#34d399;--warn:#ffb300;--danger:#ff5252;--crit:#ff3b5c;color-scheme:dark}
        *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 "IBM Plex Sans Arabic","Segoe UI",Tahoma,sans-serif}
        main{max-width:1040px;margin:0 auto;padding:28px 20px 60px}
        .mono{font-family:"IBM Plex Mono","Cascadia Mono",Consolas,monospace;font-size:.92em}.ltr{direction:ltr;unicode-bidi:isolate}.muted{color:var(--muted)}
        .top{display:flex;justify-content:space-between;align-items:center;gap:12px;border-bottom:1px solid var(--rule);padding-bottom:14px;margin-bottom:18px}
        .brand{display:flex;gap:10px;align-items:center}.brand b{display:block;letter-spacing:.2em;color:var(--accent-text)}.brand small{letter-spacing:.32em;color:var(--muted);font-size:10px}
        .meta{color:var(--muted);font-size:13px}
        .banner{border-radius:8px;padding:10px 14px;margin:10px 0;font-weight:600}.banner.demo{background:#2a1d0d;border:1px solid #6b3d0c;color:#ffb066}.banner.warn{background:#33270a;border:1px solid #6b5212;color:var(--warn)}
        .overview{display:grid;grid-template-columns:220px 1fr;gap:18px;align-items:stretch}
        @media(max-width:700px){.overview{grid-template-columns:1fr}}
        .score{background:var(--panel);border:1px solid var(--rule);border-radius:12px;padding:20px;text-align:center}
        .score .num{font-size:64px;font-weight:700;line-height:1;font-variant-numeric:tabular-nums}.score .of{color:var(--muted)}.score .verdict{margin-top:10px;font-weight:700;letter-spacing:.04em}
        .score.low .num,.score.low .verdict{color:var(--ok)}.score.med .num,.score.med .verdict{color:var(--warn)}.score.high .num,.score.high .verdict{color:var(--danger)}.score.crit .num,.score.crit .verdict{color:var(--crit)}
        .file{background:var(--panel);border:1px solid var(--rule);border-radius:12px;padding:16px 20px;min-width:0}.file h1{margin:0 0 8px;font-size:22px;overflow-wrap:anywhere}
        dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
        .disclaimer{color:var(--muted);font-size:13px;border-inline-start:3px solid var(--accent);padding-inline-start:10px}
        section{margin-top:28px}h2{font-size:12px;letter-spacing:.18em;text-transform:uppercase;color:var(--accent-text);margin:0 0 12px}h3{margin:0;font-size:16px}
        .why{list-style:none;padding:0;margin:0;display:grid;gap:6px}.why li{background:var(--panel);border:1px solid var(--rule);border-radius:8px;padding:8px 12px}.pts{display:inline-block;min-width:44px;font-weight:700;color:var(--accent-text);font-variant-numeric:tabular-nums}
        .finding{background:var(--panel);border:1px solid var(--rule);border-inline-start:4px solid var(--rule);border-radius:10px;padding:12px 16px;margin-bottom:10px}
        .finding.crit{border-inline-start-color:var(--crit)}.finding.high{border-inline-start-color:var(--danger)}.finding.med{border-inline-start-color:var(--warn)}.finding.low{border-inline-start-color:var(--ok)}
        .fhead{display:flex;flex-wrap:wrap;gap:10px;align-items:center}.rule{color:var(--muted);margin-inline-start:auto}
        .badge{display:inline-block;font-size:12px;font-weight:700;border-radius:999px;padding:1px 10px;border:1px solid var(--rule)}
        .badge.crit{color:var(--crit);border-color:#7a1f30;background:#3a1420}.badge.high{color:var(--danger);border-color:#6b2a2c;background:#3a1a1c}.badge.med{color:var(--warn);border-color:#6b5212;background:#33270a}.badge.low{color:var(--ok);border-color:#1f5a45;background:#10302a}.badge.info{color:var(--muted)}
        pre{background:var(--field);border:1px solid var(--rule);border-radius:6px;padding:8px 10px;white-space:pre-wrap;overflow-wrap:anywhere;direction:ltr;text-align:left;font-family:"IBM Plex Mono",Consolas,monospace;font-size:12.5px;margin:6px 0}
        details summary{cursor:pointer;color:var(--muted);margin-top:6px}
        .chain{background:var(--panel);border:1px solid var(--rule);border-radius:10px;padding:12px 16px;margin-bottom:10px}.chain ol{margin:8px 0 0;padding-inline-start:22px}.step{display:inline-block;min-width:110px;color:var(--accent-text);font-weight:600}
        .tree,.tree ul{list-style:none;margin:0;padding-inline-start:18px;border-inline-start:1px solid var(--rule)}.tree{border:0;padding:0}.tree li{margin:6px 0}.pname{font-weight:600}.cmd{color:var(--muted);font-size:12px;overflow-wrap:anywhere}
        .tag{font-size:11px;border:1px solid var(--accent);color:var(--accent-text);border-radius:999px;padding:0 6px}.tag.warn{border-color:var(--warn);color:var(--warn)}
        table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--rule);border-radius:10px;overflow:hidden;font-size:13.5px;margin-bottom:10px}
        th{color:var(--muted);font-weight:500;text-align:start;padding:8px 10px;border-bottom:1px solid var(--rule)}td{padding:7px 10px;border-bottom:1px solid #23232b;overflow-wrap:anywhere}
        tr.high td:first-child,tr.crit td:first-child{box-shadow:inset 3px 0 0 var(--danger)}
        .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px}.tile{background:var(--panel);border:1px solid var(--rule);border-radius:10px;padding:10px 14px}.tile h4{margin:0 0 6px;color:var(--muted);font-weight:500}.tile p{margin:0;font-variant-numeric:tabular-nums}
        .cols{margin-bottom:10px}
        footer{margin-top:40px;border-top:1px solid var(--rule);padding-top:14px;color:var(--muted);font-size:12.5px}
        """;
}
