using System.Globalization;
using System.Reflection;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Indicators;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using Engine = Blazma.Analysis.Engine;

namespace Blazma.Reporting;

/// <summary>
/// A printable PDF report (A4, light page with the Blazma orange accent), in Arabic (right to
/// left) or English. Laid out and drawn by the program itself: no browser or script engine sees
/// the sample's strings, and every value is redacted, length-limited and drawn as plain text.
/// </summary>
public sealed class PdfReportExporter : IReportExporter
{
    private const int MaxText = 400;
    private const int MaxFindings = 60;
    private const int MaxRows = 120;

    private static readonly Lock FontGate = new();
    private static bool _fontsReady;

    private readonly Func<bool, Redactor> _redactorFactory;

    public PdfReportExporter(Func<bool, Redactor>? redactorFactory = null)
    {
        _redactorFactory = redactorFactory ?? (redact => redact ? new Redactor() : Redactor.None);
    }

    public string Format => "PDF";
    public string FileExtension => ".pdf";

    public Task ExportAsync(AnalysisResult result, Stream destination, ExportOptions options, CancellationToken cancellationToken)
    {
        var bytes = Render(result, options, _redactorFactory(options.Redact));
        return destination.WriteAsync(bytes, cancellationToken).AsTask();
    }

    // ---- setup -------------------------------------------------------------------------------

    private const string Sans = "IBM Plex Sans Arabic";
    private const string Mono = "IBM Plex Mono";

    private static readonly Color Ink = Color.FromHex("#1C1C22");
    private static readonly Color Muted = Color.FromHex("#5F5F6B");
    private static readonly Color Rule = Color.FromHex("#E2E2E8");
    private static readonly Color Soft = Color.FromHex("#F6F6F8");
    private static readonly Color Accent = Color.FromHex("#FF6D00");
    private static readonly Color AccentSoft = Color.FromHex("#FFF1E5");
    private static readonly Color Ok = Color.FromHex("#0E9F6E");
    private static readonly Color Warn = Color.FromHex("#C27C00");
    private static readonly Color Danger = Color.FromHex("#E5383B");
    private static readonly Color Crit = Color.FromHex("#C9184A");

    /// <summary>Registers the embedded fonts once and turns off anything that reads the machine's fonts.</summary>
    private static void EnsureSetup()
    {
        lock (FontGate)
        {
            if (_fontsReady) return;
            QuestPDF.Settings.License = LicenseType.Community;
            QuestPDF.Settings.UseEnvironmentFonts = false;
            // Hostile strings may contain characters no font has; draw a placeholder instead of failing.
            QuestPDF.Settings.CheckIfAllTextGlyphsAreAvailable = false;
            var assembly = Assembly.GetExecutingAssembly();
            foreach (var name in assembly.GetManifestResourceNames().Where(n => n.StartsWith("Blazma.Reporting.Fonts.", StringComparison.Ordinal)))
            {
                using var stream = assembly.GetManifestResourceStream(name)!;
                QuestPDF.Drawing.FontManager.RegisterFont(stream);
            }
            _fontsReady = true;
        }
    }

    // ---- document ----------------------------------------------------------------------------

    internal static byte[] Render(AnalysisResult a, ExportOptions o, Redactor r)
    {
        EnsureSetup();
        var t = ReportStrings.For(o.Language);
        var lang = t.Lang;
        var ar = t.Rtl;

        string S(string? s)
        {
            var v = r.Apply(s) ?? string.Empty;
            // Control characters are dropped; long values are cut so one string cannot fill pages.
            v = new string(v.Where(c => !char.IsControl(c) || c == ' ').ToArray());
            return v.Length > MaxText ? v[..MaxText] + "…" : v;
        }
        string L(Core.Text.LocalizedText text) => S(text.Get(lang));
        // Technical values (dates, sizes, hashes, paths) keep left-to-right order inside Arabic text.
        string Ltr(string v) => ar ? "\u2066" + v + "\u2069" : v;

        var document = Document.Create(doc => doc.Page(page =>
        {
            page.Size(PageSizes.A4);
            page.Margin(34);
            page.PageColor(Colors.White);
            page.DefaultTextStyle(x => x.FontFamily(Sans).FontSize(9.5f).FontColor(Ink).LineHeight(1.35f));
            if (ar) page.ContentFromRightToLeft();

            page.Header().PaddingBottom(10).BorderBottom(1).BorderColor(Rule).Row(row =>
            {
                row.AutoItem().Width(22).Height(22).Svg(LogoSvg);
                row.ConstantItem(8);
                row.RelativeItem().Column(c =>
                {
                    c.Item().Text("BLAZMA SANDBOX").FontColor(Accent).Bold().LetterSpacing(0.15f).FontSize(10);
                    c.Item().Text(t.Title).FontColor(Muted).FontSize(8.5f);
                });
                row.AutoItem().AlignMiddle().Text(Ltr(a.StartedAt.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC")).FontFamily(Mono).FontSize(8).FontColor(Muted);
            });

            page.Content().PaddingTop(12).Column(col =>
            {
                col.Spacing(10);
                if (a.IsDemo) col.Item().Element(Banner(AccentSoft, Accent)).Text(t.Demo).Bold().FontColor(Accent);
                if (a.MonitoringInterrupted) col.Item().Element(Banner(Color.FromHex("#FFF6DB"), Warn)).Text(t.Interrupted).Bold().FontColor(Warn);

                // Overview: score card + file details
                col.Item().Row(row =>
                {
                    var color = VerdictColor(a.Risk.Verdict);
                    row.ConstantItem(150).Border(1).BorderColor(Rule).Background(Soft).Padding(12).Column(c =>
                    {
                        c.Item().AlignCenter().Text(a.Risk.Score.ToString(CultureInfo.InvariantCulture)).FontSize(40).Bold().FontColor(color);
                        c.Item().AlignCenter().Text("/ 100").FontColor(Muted);
                        c.Item().PaddingTop(6).AlignCenter().Text(VerdictText.Of(a.Risk.Verdict, lang)).Bold().FontColor(color);
                    });
                    row.ConstantItem(10);
                    row.RelativeItem().Border(1).BorderColor(Rule).Padding(12).Column(c =>
                    {
                        c.Spacing(3);
                        c.Item().Text(S(a.Sample.FileName)).FontSize(14).Bold();
                        if (a.Sample.Origin is { } origin) Field(c, t.FileInfo, Ltr($"{S(origin.ArchiveName)} → {S(origin.EntryPath)}"));
                        Field(c, "SHA-256", a.Sample.Sha256, mono: true);
                        Field(c, t.Size, Ltr(a.Sample.Size.ToString("N0", CultureInfo.InvariantCulture) + " B"));
                        Field(c, t.Type, Ltr(a.Sample.Kind + (a.Static?.Pe is { } pe ? " · " + pe.Machine : "")));
                        Field(c, t.Signature, Ltr((a.Static?.Signature.Status.ToString() ?? "-") + (a.Static?.Signature.Publisher is { } pub ? " · " + S(pub) : "")));
                        if (a.Static?.ImpHash is { } imp) Field(c, "Imphash", imp, mono: true);
                        Field(c, t.Duration, Ltr(a.Duration is { } d ? d.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) + " s" : "-"));
                        Field(c, t.Provider, Ltr(S(a.ProviderId) + " · " + a.Options.Network));
                    });
                });
                col.Item().BorderLeft(ar ? 0 : 3).BorderRight(ar ? 3 : 0).BorderColor(Accent).PaddingHorizontal(8)
                    .Text(ar ? RiskAssessment.DisclaimerAr : RiskAssessment.Disclaimer).FontColor(Muted).FontSize(8.5f);

                // Why this score
                Section(col, t.WhyScore, c =>
                {
                    if (a.Risk.Contributions.Count == 0) { c.Item().Text(t.NoFindings).FontColor(Muted); return; }
                    foreach (var contribution in a.Risk.Contributions)
                        c.Item().Row(row =>
                        {
                            row.ConstantItem(36).Text("+" + contribution.Points.ToString(CultureInfo.InvariantCulture)).Bold().FontColor(Accent);
                            row.RelativeItem().Text(L(contribution.Title) + (contribution.Capped ? (ar ? " (بلغ الحد الأقصى)" : " (capped)") : ""));
                        });
                });

                // Findings
                Section(col, t.ImportantFindings, c =>
                {
                    if (a.Findings.Count == 0) { c.Item().Text(t.NoFindings).FontColor(Muted); return; }
                    foreach (var f in a.Findings.OrderByDescending(x => x.Points).Take(MaxFindings))
                    {
                        var color = SeverityColor(f.Severity);
                        c.Item().ShowEntire().BorderLeft(ar ? 0 : 3).BorderRight(ar ? 3 : 0).BorderColor(color).Background(Soft).Padding(8).Column(fc =>
                        {
                            fc.Spacing(3);
                            fc.Item().Row(row =>
                            {
                                row.AutoItem().Text(VerdictText.Of(f.Severity, lang)).Bold().FontColor(color).FontSize(8.5f);
                                row.ConstantItem(8);
                                row.RelativeItem().Text(L(f.Title)).Bold();
                                row.AutoItem().Text($"+{f.Points}").Bold().FontColor(Accent);
                            });
                            fc.Item().Text(L(f.Explanation));
                            var meta = f.RuleId + (f.AttackTechniques.Count > 0 ? " · ATT&CK " + string.Join(", ", f.AttackTechniques) : "");
                            fc.Item().Text(Ltr(meta)).FontFamily(Mono).FontSize(7.5f).FontColor(Muted);
                            foreach (var ev in f.Evidence.Take(4))
                            {
                                fc.Item().Text("• " + L(ev.Description)).FontSize(8.5f);
                                if (ev.Technical is { Length: > 0 } tech) fc.Item().PaddingHorizontal(8).Text(Ltr(S(tech))).FontFamily(Mono, Sans).FontSize(7.5f).FontColor(Muted);
                            }
                            if (f.Evidence.Count > 4) fc.Item().Text($"… +{f.Evidence.Count - 4}").FontColor(Muted).FontSize(8);
                        });
                    }
                    if (a.Findings.Count > MaxFindings) c.Item().Text($"… +{a.Findings.Count - MaxFindings}").FontColor(Muted);
                });

                // Behavior chains
                if (a.Chains.Count > 0)
                    Section(col, t.BehaviorChains, c =>
                    {
                        foreach (var chain in a.Chains)
                        {
                            c.Item().Text(L(chain.Title)).Bold().FontColor(SeverityColor(chain.Severity));
                            foreach (var step in chain.Steps.Take(12))
                                c.Item().PaddingHorizontal(8).Text($"{(ar ? "←" : "→")} " + Ltr($"{step.Kind}  {S(step.Target)}")).FontSize(8.5f);
                        }
                    });

                // Persistence
                if (a.Persistence.Count > 0)
                    Section(col, t.Persistence, c =>
                    {
                        foreach (var p in a.Persistence)
                        {
                            c.Item().Text(L(Engine.PersistenceNames.Of(p.Technique)) + " · " + VerdictText.Of(p.Severity, lang)).Bold().FontColor(SeverityColor(p.Severity));
                            c.Item().Text(L(p.Explanation)).FontSize(8.5f);
                            c.Item().PaddingHorizontal(8).Text(Ltr(S(p.Target) + (p.Value is null ? "" : " = " + S(p.Value)))).FontFamily(Mono, Sans).FontSize(7.5f).FontColor(Muted);
                        }
                    });

                // Network
                var dns = a.Events.Where(e => e.Action == EventAction.DnsQuery).Select(e => e.Detail(DetailKeys.QueryName) ?? e.Target ?? "?").Distinct().Take(MaxRows).ToList();
                var conns = a.Events.Where(e => e.Action == EventAction.NetworkConnect)
                    .Select(e => $"{e.Detail(DetailKeys.RemoteAddress) ?? e.Target}:{e.Detail(DetailKeys.RemotePort)}  ({e.ProcessName})").Distinct().Take(MaxRows).ToList();
                var http = a.Events.Where(e => e.Action == EventAction.HttpRequest)
                    .Select(e => $"{e.Detail(DetailKeys.HttpMethod)} {e.Detail(DetailKeys.HttpHost)}{e.Detail(DetailKeys.HttpPath)}").Distinct().Take(MaxRows).ToList();
                if (dns.Count + conns.Count + http.Count > 0)
                    Section(col, t.Network, c =>
                    {
                        Lines(c, t.Dns, dns.Select(x => Ltr(S(x))));
                        Lines(c, t.Connections, conns.Select(x => Ltr(S(x))));
                        Lines(c, ar ? "طلبات الويب (إنترنت وهمي)" : "Web requests (simulated internet)", http.Select(x => Ltr(S(x))));
                    });

                // Static: capabilities, YARA
                if (o.IncludeStatic && a.Static is { } st && (st.Capabilities.Count > 0 || st.YaraMatches.Count > 0))
                    Section(col, t.StaticDetails, c =>
                    {
                        foreach (var cap in st.Capabilities.Take(MaxRows))
                            c.Item().Text($"{cap.Id}  {L(cap.Name)}").FontSize(8.5f);
                        foreach (var m in a.AllYaraMatches.Take(MaxRows))
                            c.Item().Text($"YARA  {S(m.Rule)}  [{S(m.Source)}]").FontFamily(Mono, Sans).FontSize(8);
                    });

                // Created files and memory
                if (a.DroppedFiles.Count > 0 || a.MemoryArtifacts.Count > 0)
                    Section(col, ar ? "الملفات المُنشأة والذاكرة" : "Created files and memory", c =>
                    {
                        foreach (var f in a.DroppedFiles.Take(MaxRows))
                            c.Item().Text($"{S(f.OriginalPath)}  ·  {f.Size.ToString("N0", CultureInfo.InvariantCulture)} B  ·  {f.Sha256}").FontFamily(Mono, Sans).FontSize(7.5f);
                        foreach (var m in a.MemoryArtifacts.Take(MaxRows))
                            c.Item().Text($"{S(m.ProcessName)} ({m.ProcessId})  0x{m.BaseAddress:X}  {m.Kind}  {m.Protection}").FontFamily(Mono, Sans).FontSize(7.5f);
                    });

                // Indicators
                if (o.IncludeIndicators && a.Indicators.Count > 0)
                    Section(col, t.Indicators, c => c.Item().Table(table =>
                    {
                        table.ColumnsDefinition(cd => { cd.ConstantColumn(80); cd.RelativeColumn(); cd.ConstantColumn(80); });
                        table.Header(h =>
                        {
                            foreach (var head in new[] { t.Type, t.Value, t.Status })
                                h.Cell().BorderBottom(1).BorderColor(Rule).PaddingVertical(3).Text(head).FontColor(Muted).FontSize(8);
                        });
                        foreach (var i in a.Indicators.Take(MaxRows))
                        {
                            table.Cell().PaddingVertical(2).Text(i.Type.ToString()).FontSize(8);
                            table.Cell().PaddingVertical(2).Text(S(i.Value)).FontFamily(Mono, Sans).FontSize(7.5f);
                            table.Cell().PaddingVertical(2).Text(i.Status.ToString()).FontSize(8).FontColor(IndicatorColor(i.Status));
                        }
                    }));

                // Reputation
                if (a.Reputation.Count > 0)
                    Section(col, ar ? "السمعة (بالبصمة فقط)" : "Reputation (hash only)", c =>
                    {
                        foreach (var rep in a.Reputation)
                            c.Item().Text($"{S(rep.ProviderName)}: {rep.Verdict}{(rep.Detections is { } d ? $" ({d}/{rep.Engines})" : "")}{(rep.Family is { } fam ? " · " + S(fam) : "")}").FontSize(8.5f);
                    });

                col.Item().PaddingTop(10).BorderTop(1).BorderColor(Rule).PaddingTop(6).Column(c =>
                {
                    c.Item().Text(t.LocalFirst).FontColor(Muted).FontSize(8);
                    if (o.Redact) c.Item().Text(t.Redacted).FontColor(Muted).FontSize(8);
                });
            });

            page.Footer().Row(row =>
            {
                row.RelativeItem().Text(S(a.Sample.FileName) + " · " + a.Sample.Sha256[..16]).FontFamily(Mono, Sans).FontSize(7).FontColor(Muted);
                row.AutoItem().ContentFromLeftToRight().Text(x =>
                {
                    x.DefaultTextStyle(s => s.FontSize(7.5f).FontColor(Muted));
                    x.CurrentPageNumber();
                    x.Span(" / ");
                    x.TotalPages();
                });
            });
        }));
        document.WithMetadata(new DocumentMetadata
        {
            Title = $"{a.Sample.FileName} · Blazma Sandbox",
            Author = "Blazma Sandbox",
            Creator = "Blazma Sandbox",
            Producer = "Blazma Sandbox",
            Subject = t.Title,
            Language = lang,
        });
        return document.GeneratePdf();
    }

    // ---- building blocks ---------------------------------------------------------------------

    private static Func<IContainer, IContainer> Banner(Color background, Color border) =>
        c => c.Background(background).Border(1).BorderColor(border).Padding(8);

    private static void Field(ColumnDescriptor c, string label, string value, bool mono = false) =>
        c.Item().Row(row =>
        {
            row.ConstantItem(92).Text(label).FontColor(Muted).FontSize(8.5f);
            var text = row.RelativeItem().Text(value).FontSize(mono ? 8 : 9);
            if (mono) text.FontFamily(Mono, Sans);
        });

    private static void Section(ColumnDescriptor col, string title, Action<ColumnDescriptor> body) =>
        col.Item().Column(c =>
        {
            c.Spacing(4);
            c.Item().PaddingTop(4).Text(title).FontSize(11).Bold().FontColor(Accent);
            body(c);
        });

    private static void Lines(ColumnDescriptor c, string title, IEnumerable<string> lines)
    {
        var list = lines.ToList();
        if (list.Count == 0) return;
        c.Item().Text(title).Bold().FontSize(9);
        foreach (var line in list) c.Item().PaddingHorizontal(8).Text(line).FontFamily(Mono, Sans).FontSize(7.5f);
    }

    private static Color VerdictColor(Verdict v) => v switch
    {
        Verdict.CriticalBehavior => Crit,
        Verdict.HighRiskBehavior => Danger,
        Verdict.Suspicious => Warn,
        _ => Ok,
    };

    private static Color SeverityColor(Severity s) => s switch
    {
        Severity.Critical => Crit,
        Severity.High => Danger,
        Severity.Medium => Warn,
        Severity.Low => Ok,
        _ => Muted,
    };

    private static Color IndicatorColor(IndicatorStatus s) => s switch
    {
        IndicatorStatus.HighRisk or IndicatorStatus.WatchlistMatch => Danger,
        IndicatorStatus.Suspicious => Warn,
        _ => Muted,
    };

    private const string LogoSvg = """<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hx" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#FFB300"/><stop offset="1" stop-color="#FF3D00"/></linearGradient></defs><path d="M50,3 L91,26.5 L91,73.5 L50,97 L9,73.5 L9,26.5 Z" fill="url(#hx)"/><path d="M50,24 L72,36 L72,62 L50,74 L28,62 L28,36 Z M28,36 L50,48 L72,36 M50,48 L50,74" fill="none" stroke="#fff" stroke-width="6" stroke-linejoin="round" stroke-linecap="round"/></svg>""";
}
