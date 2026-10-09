using System.Collections.ObjectModel;
using Avalonia.Media.Imaging;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Analysis;
using Blazma.Core.Attack;
using Blazma.Core.Events;
using Blazma.Core.Samples;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Blazma.App.ViewModels;

public sealed class ScreenshotItem(Bitmap image, TimeSpan at)
{
    public Bitmap Image { get; } = image;
    public string Time { get; } = Fmt.Relative(at, ms: false);
}

public sealed class DroppedFileRow(DroppedFileInfo d)
{
    public string Name { get; } = System.IO.Path.GetFileName(d.OriginalPath.Replace('\\', '/'));
    public string Path { get; } = d.OriginalPath;
    public string Process { get; } = d.ProcessName;
    public string Size { get; } = Fmt.Size(d.Size);
    public string Sha256 { get; } = d.Sha256;
    public string Kind { get; } = d.Static is { } s ? Loc.T("Kind" + s.Sample.Kind) : "—";
    public string Notes { get; } = string.Join(" · ", new[]
    {
        d.Static?.Signature.Status == SignatureStatus.Valid ? Loc.F("SignedBy", d.Static.Signature.Publisher ?? "?") : null,
        d.Static is { Capabilities.Count: > 0 } c ? Loc.F("CapabilitiesCount", c.Capabilities.Count) : null,
        d.Static is { YaraMatches.Count: > 0 } y ? Loc.F("YaraCount", y.YaraMatches.Count) : null,
        d.Static?.ImpHash is { } h ? "imphash " + h : null,
    }.Where(x => x is not null));
}

public sealed class MemoryRow(MemoryArtifact m)
{
    public string Process { get; } = $"{m.ProcessName} ({m.ProcessId})";
    public string Address { get; } = $"0x{m.BaseAddress:X}";
    public string Size { get; } = Fmt.Size(m.Size);
    public string Protection { get; } = m.Protection;
    public string Kind { get; } = Loc.T("Mem" + m.Kind);
    public bool HasPe { get; } = m.HasPeHeader;
    public string Notes { get; } = string.Join(" · ", new[]
    {
        m.HasPeHeader ? Loc.T("MemHasPe") : null,
        m.YaraMatches.Count > 0 ? Loc.F("YaraCount", m.YaraMatches.Count) : null,
        m.Artifacts.Count > 0 ? Loc.F("ArtifactsCount", m.Artifacts.Count) : null,
    }.Where(x => x is not null));
}

public sealed record ArtifactRow(string Kind, string Value, string Source);

public sealed class CapabilityRow(Capability c)
{
    public string Name { get; } = c.Name.Get(Loc.Instance.Code);
    public string Description { get; } = c.Description.Get(Loc.Instance.Code);
    public Severity Severity { get; } = c.Severity;
    public string Namespace { get; } = c.Namespace;
    public string Attack { get; } = string.Join(" ", c.AttackTechniques);
    public string Evidence { get; } = string.Join("\n", c.Evidence.Take(6));
}

public sealed class YaraRow(YaraMatch m)
{
    public string Rule { get; } = m.Rule;
    public string Family { get; } = m.Family ?? string.Empty;
    public bool HasFamily => Family.Length > 0;
    public string Target { get; } = m.Target;
    public string Source { get; } = m.Source;
    public string Strings { get; } = string.Join("  ", m.Strings.Take(6).Select(s => $"{s.Identifier}@0x{s.Offset:X}"));
}

public sealed class WebRequestRow(AnalysisEvent e)
{
    public AnalysisEvent Event { get; } = e;
    public string Time { get; } = Fmt.Relative(e.RelativeTime);
    public string Process { get; } = e.ProcessName;
    public string Method { get; } = e.Action == EventAction.TlsHandshake ? "TLS" : e.Detail(DetailKeys.HttpMethod) ?? "?";
    public string Target { get; } = e.Action == EventAction.TlsHandshake ? e.Detail(DetailKeys.ServerName) ?? e.Target ?? "?" : e.Target ?? "?";
    public string Detail { get; } = string.Join(" · ", new[] { e.Detail(DetailKeys.UserAgent), e.Detail(DetailKeys.BodyPreview) }.Where(x => !string.IsNullOrEmpty(x)));
    public bool HasDetail => Detail.Length > 0;
}

public sealed record AttackCell(string Id, string Name, int Count);

public sealed class AttackColumn(string tactic, IReadOnlyList<AttackCell> cells)
{
    public string Tactic { get; } = tactic;
    public IReadOnlyList<AttackCell> Cells { get; } = cells;
}

public sealed partial class ReportViewModel
{
    public ObservableCollection<ScreenshotItem> Screenshots { get; } = [];
    public ObservableCollection<DroppedFileRow> DroppedFiles { get; } = [];
    public ObservableCollection<MemoryRow> MemoryRegions { get; } = [];
    public ObservableCollection<ArtifactRow> ExtractedValues { get; } = [];
    public ObservableCollection<CapabilityRow> Capabilities { get; } = [];
    public ObservableCollection<YaraRow> YaraMatches { get; } = [];
    public ObservableCollection<WebRequestRow> WebRequests { get; } = [];
    public ObservableCollection<AttackColumn> AttackMatrix { get; } = [];
    public ObservableCollection<ReputationRow> ReputationResults { get; } = [];

    [ObservableProperty] private ScreenshotItem? _selectedScreenshot;

    public bool HasScreenshots => Screenshots.Count > 0;
    public bool HasNoScreenshots => Screenshots.Count == 0;
    public bool HasDropped => DroppedFiles.Count > 0;
    public bool HasMemory => MemoryRegions.Count > 0;
    public bool HasExtracted => ExtractedValues.Count > 0;
    public bool HasNoArtifacts => !HasDropped && !HasMemory && !HasExtracted;
    public bool HasCapabilities => Capabilities.Count > 0;
    public bool HasYara => YaraMatches.Count > 0;
    public bool HasNoCode => !HasCapabilities && !HasYara;
    public bool HasWebRequests => WebRequests.Count > 0;
    public bool HasAttack => AttackMatrix.Count > 0;
    public bool HasNoAttack => AttackMatrix.Count == 0;
    public bool HasReputation => ReputationResults.Count > 0;
    public string ImpHash => Result?.Static?.ImpHash ?? "—";
    public bool HasPcap => Result?.PcapFile is not null;

    private void BuildArtifacts()
    {
        var r = Result!;
        var folder = _paths.ArtifactsFor(r.AnalysisId);

        foreach (var s in Screenshots) s.Image.Dispose();
        Screenshots.Clear();
        foreach (var shot in r.Screenshots)
        {
            var path = System.IO.Path.GetFullPath(System.IO.Path.Combine(folder, shot.FileName));
            // Only files inside this analysis' folder; the PNGs were written by the host itself.
            if (!path.StartsWith(System.IO.Path.GetFullPath(folder), StringComparison.OrdinalIgnoreCase) || !File.Exists(path)) continue;
            try { Screenshots.Add(new ScreenshotItem(new Bitmap(path), shot.RelativeTime)); }
            catch (Exception ex) when (ex is IOException or ArgumentException or InvalidOperationException) { }
        }
        SelectedScreenshot = Screenshots.LastOrDefault();

        DroppedFiles.Clear();
        foreach (var d in r.DroppedFiles) DroppedFiles.Add(new DroppedFileRow(d));
        MemoryRegions.Clear();
        foreach (var m in r.MemoryArtifacts) MemoryRegions.Add(new MemoryRow(m));
        ExtractedValues.Clear();
        foreach (var a in r.Artifacts.Take(500)) ExtractedValues.Add(new ArtifactRow(Loc.T("Art" + a.Kind), a.Value, a.Source));

        Capabilities.Clear();
        foreach (var c in r.Static?.Capabilities ?? []) Capabilities.Add(new CapabilityRow(c));
        YaraMatches.Clear();
        foreach (var y in r.AllYaraMatches.Take(200)) YaraMatches.Add(new YaraRow(y));

        WebRequests.Clear();
        foreach (var e in r.Events.Where(e => e.Action is EventAction.HttpRequest or EventAction.TlsHandshake)) WebRequests.Add(new WebRequestRow(e));

        ReputationResults.Clear();
        foreach (var rep in r.Reputation)
            ReputationResults.Add(new ReputationRow(rep.ProviderName, Loc.T("Rep" + rep.Verdict),
                rep.Error ?? string.Join(" · ", new[] { rep.Detections is { } d ? Loc.F("RepDetections", d, rep.Engines ?? 0) : null, rep.Family is { Length: > 0 } f ? Loc.F("RepFamily", f) : null }.Where(x => x is not null)),
                rep.Verdict is ReputationVerdict.Malicious or ReputationVerdict.Suspicious, rep.Link));

        BuildAttackMatrix(r);

        foreach (var name in new[] { nameof(HasScreenshots), nameof(HasNoScreenshots), nameof(HasDropped), nameof(HasMemory), nameof(HasExtracted), nameof(HasNoArtifacts),
                     nameof(HasCapabilities), nameof(HasYara), nameof(HasNoCode), nameof(HasWebRequests), nameof(HasAttack), nameof(HasNoAttack), nameof(HasReputation),
                     nameof(ImpHash), nameof(HasPcap) })
            OnPropertyChanged(name);
    }

    /// <summary>ATT&amp;CK techniques from findings (observed) and capabilities (potential), laid out by tactic in matrix order.</summary>
    private void BuildAttackMatrix(AnalysisResult r)
    {
        AttackMatrix.Clear();
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var id in r.Findings.SelectMany(f => f.AttackTechniques).Concat((r.Static?.Capabilities ?? []).SelectMany(c => c.AttackTechniques)))
        {
            var technique = AttackCatalog.TryGet(id, out var t) ? t : AttackCatalog.TryGetReplacement(id, out var replaced) ? replaced : null;
            if (technique is null) continue;
            counts[technique.Id] = counts.GetValueOrDefault(technique.Id) + 1;
        }
        var arabic = Loc.Instance.IsArabic;
        foreach (var tactic in AttackCatalog.Tactics)
        {
            var cells = counts.Keys
                .Select(id => AttackCatalog.TryGet(id, out var t) ? t : null)
                .Where(t => t is not null && t.Tactics.Contains(tactic.ShortName, StringComparer.Ordinal))
                .OrderBy(t => t!.Id, StringComparer.Ordinal)
                .Select(t => new AttackCell(t!.Id, t.Name, counts[t.Id]))
                .ToList();
            if (cells.Count > 0) AttackMatrix.Add(new AttackColumn(arabic ? tactic.NameAr : tactic.Name, cells));
        }
    }

    [RelayCommand] private void OpenAttack(string? id) { if (id is not null && AttackCatalog.TryGet(id, out var t)) _main.OpenUrl(t.Url); }
    [RelayCommand] private void OpenLink(string? url) => _main.OpenUrl(url);
    [RelayCommand] private void OpenArtifactsFolder() { if (Result is not null) _main.OpenFolder(_paths.ArtifactsFor(Result.AnalysisId)); }
}
