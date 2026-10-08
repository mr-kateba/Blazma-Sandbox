using System.Collections.ObjectModel;
using Avalonia.Threading;
using Blazma.Analysis.Engine;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Processes;
using Blazma.Core.Samples;
using Blazma.Intelligence;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Blazma.App.ViewModels;

/// <summary>
/// The report: what happened, why it matters, and the evidence. Every list filters in
/// memory over the loaded events and is shown in virtualised lists, so 100k+ events stay
/// responsive. Raw events page directly from the database.
/// </summary>
public sealed partial class ReportViewModel : PageViewModel
{
    private readonly MainViewModel _main;
    private readonly IAnalysisRepository _repository;
    private readonly ExportService _export;
    private readonly AskBlazma _ask = new();
    private List<TimelineRow> _allTimeline = [];
    private HashSet<long> _highlight = [];
    private int _rawOffset;

    public ReportViewModel(MainViewModel main, IAnalysisRepository repository, ExportService export)
    {
        _main = main;
        _repository = repository;
        _export = export;
        CategoryChips =
        [
            new FilterChip("All", "FilterAll", true), new FilterChip("Process", "CatProcess"), new FilterChip("File", "CatFile"),
            new FilterChip("Registry", "CatRegistry"), new FilterChip("Network", "CatNetwork"), new FilterChip("Persistence", "CatPersistence"),
            new FilterChip("System", "CatSystem"),
        ];
        foreach (var c in CategoryChips) c.Toggled += OnChipToggled;
        FileChips = [new FilterChip("All", "FilterAll", true), new FilterChip("FileCreate", "ActFileCreate"), new FilterChip("FileWrite", "ActFileWrite"),
            new FilterChip("FileDelete", "ActFileDelete"), new FilterChip("FileRename", "ActFileRename"), new FilterChip("Executed", "FileExecuted")];
        foreach (var c in FileChips) c.Toggled += (s, _) => { ExclusiveChip(FileChips, (FilterChip)s!); ApplyFileFilter(); };
    }

    public override string NavKey => "History";

    public AnalysisResult? Result { get; private set; }

    [ObservableProperty] private bool _isLoading = true;
    [ObservableProperty] private int _selectedTab;
    [ObservableProperty] private FindingItem? _selectedFinding;
    [ObservableProperty] private ProcessItem? _selectedProcess;
    [ObservableProperty] private string _timelineSearch = string.Empty;
    [ObservableProperty] private SeverityOption? _minSeverity;
    [ObservableProperty] private string? _processFilter;
    [ObservableProperty] private string _fromSeconds = string.Empty;
    [ObservableProperty] private string _toSeconds = string.Empty;
    [ObservableProperty] private string _fileSearch = string.Empty;
    [ObservableProperty] private string _registrySearch = string.Empty;
    [ObservableProperty] private bool _registryPersistenceOnly;
    [ObservableProperty] private bool _showBackgroundProcesses;
    [ObservableProperty] private string _question = string.Empty;
    [ObservableProperty] private string _timelineCount = string.Empty;
    [ObservableProperty] private bool _hasMoreRaw;

    public ObservableCollection<FilterChip> CategoryChips { get; }
    public ObservableCollection<FilterChip> FileChips { get; }
    public ObservableCollection<SeverityOption> SeverityOptions { get; } = [];
    public ObservableCollection<string> ProcessNames { get; } = [];
    public ObservableCollection<SummaryRow> Summary { get; } = [];
    public ObservableCollection<ContributionRow> Contributions { get; } = [];
    public ObservableCollection<FindingItem> Findings { get; } = [];
    public ObservableCollection<ChainItem> Chains { get; } = [];
    public ObservableCollection<TimelineRow> Timeline { get; } = [];
    public ObservableCollection<ProcessItem> ProcessRoots { get; } = [];
    public ObservableCollection<DetailRow> ProcessDetails { get; } = [];
    public ObservableCollection<TimelineRow> ProcessActivity { get; } = [];
    public ObservableCollection<FileRow> Files { get; } = [];
    public ObservableCollection<RegistryRow> Registry { get; } = [];
    public ObservableCollection<DnsRow> Dns { get; } = [];
    public ObservableCollection<ConnectionRow> Connections { get; } = [];
    public ObservableCollection<NetworkTreeNode> NetworkTree { get; } = [];
    public ObservableCollection<PersistenceItem> Persistence { get; } = [];
    public ObservableCollection<IndicatorGroup> Indicators { get; } = [];
    public ObservableCollection<ChangeTile> ChangeTiles { get; } = [];
    public ObservableCollection<ChangeGroup> ChangeGroups { get; } = [];
    public ObservableCollection<TimelineRow> RawEvents { get; } = [];
    public ObservableCollection<ChatMessage> Chat { get; } = [];
    public ObservableCollection<string> Suggestions { get; } = [];

    private List<FileRow> _allFiles = [];
    private List<RegistryRow> _allRegistry = [];

    public string FileName => Result?.Sample.FileName ?? string.Empty;
    public int Score => Result?.Risk.Score ?? 0;
    public Verdict Verdict => Result?.Risk.Verdict ?? Verdict.LowRisk;
    public string VerdictText => Fmt.Verdict(Verdict).ToUpperInvariant();
    public bool IsDemo => Result?.IsDemo == true;
    public bool IsFailed => Result is { FinalStage: not AnalysisStage.Completed };
    public string? FailureReason => Result?.FailureReason;
    public bool MonitoringInterrupted => Result?.MonitoringInterrupted == true;
    public string Sha256 => Result?.Sample.Sha256 ?? string.Empty;
    public string MetaLine => Result is null ? string.Empty : $"{Fmt.Date(Result.StartedAt)} · {Fmt.Duration(Result.Duration)} · {Fmt.Provider(Result.ProviderId)} · {Loc.F("EventsCount", Result.Events.Count)}";
    public string Disclaimer => Loc.Instance.IsArabic ? RiskAssessment.DisclaimerAr : RiskAssessment.Disclaimer;
    public string NoiseNote => Result is { SuppressedNoiseEvents: > 0 } r ? Loc.F("NoiseNote", r.SuppressedNoiseEvents) : string.Empty;
    public bool HasNoiseNote => Result is { SuppressedNoiseEvents: > 0 };
    public bool HasFindings => Findings.Count > 0;
    public bool HasNoFindings => Findings.Count == 0;
    public bool HasChains => Chains.Count > 0;
    public bool HasFindingSelected => SelectedFinding is not null;
    public bool HasProcessSelected => SelectedProcess is not null;
    public bool HasPersistence => Persistence.Count > 0;
    public bool HasNoPersistence => Persistence.Count == 0;
    public bool HasChanges => Result?.SystemChanges is not null;
    public bool HasNoChanges => Result?.SystemChanges is null;
    public bool HasNoNetwork => Dns.Count == 0 && Connections.Count == 0;
    public string RuleErrors => string.Empty;

    partial void OnSelectedFindingChanged(FindingItem? value) => OnPropertyChanged(nameof(HasFindingSelected));
    partial void OnSelectedProcessChanged(ProcessItem? value) { BuildProcessDetails(); OnPropertyChanged(nameof(HasProcessSelected)); }
    partial void OnTimelineSearchChanged(string value) => ApplyTimelineFilter();
    partial void OnMinSeverityChanged(SeverityOption? value) => ApplyTimelineFilter();
    partial void OnProcessFilterChanged(string? value) => ApplyTimelineFilter();
    partial void OnFromSecondsChanged(string value) => ApplyTimelineFilter();
    partial void OnToSecondsChanged(string value) => ApplyTimelineFilter();
    partial void OnFileSearchChanged(string value) => ApplyFileFilter();
    partial void OnRegistrySearchChanged(string value) => ApplyRegistryFilter();
    partial void OnRegistryPersistenceOnlyChanged(bool value) => ApplyRegistryFilter();
    partial void OnShowBackgroundProcessesChanged(bool value) => BuildProcessTree();

    /// <summary>Raised when the view should scroll the timeline to a row.</summary>
    public event EventHandler<TimelineRow>? ScrollTimelineTo;

    public async Task LoadAsync(Guid id, int tab = 0, long? focusSequence = null)
    {
        IsLoading = true;
        Result = await Task.Run(() => _repository.LoadAsync(id, includeEvents: true, CancellationToken.None));
        if (Result is null)
        {
            IsLoading = false;
            await _main.Dialogs.ErrorAsync(Loc.T("ReportMissingTitle"), Loc.T("ReportMissingBody"), null, canRetry: false);
            _main.Navigate("History");
            return;
        }
        Build();
        IsLoading = false;
        SelectedTab = tab;
        if (focusSequence is { } seq) ShowSequencesInTimeline([seq]);
    }

    private void Build()
    {
        var r = Result!;
        var lang = Loc.Instance.Code;
        _allTimeline = r.Events.Select(e => new TimelineRow(e)).ToList();
        _highlight = [];

        SeverityOptions.Clear();
        foreach (var s in Enum.GetValues<Severity>()) SeverityOptions.Add(new SeverityOption(s));
        MinSeverity = SeverityOptions[0];
        ProcessNames.Clear();
        ProcessNames.Add(Loc.T("AllProcesses"));
        foreach (var n in r.Events.Select(e => e.ProcessName).Where(n => n.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase)) ProcessNames.Add(n);
        ProcessFilter = ProcessNames[0];

        // Overview
        Summary.Clear();
        var persist = r.Persistence.Count(p => p.ByAnalyzedTree || p.PointsToDroppedFile);
        var external = r.Events.Count(e => e.Action == EventAction.NetworkConnect && NetworkMap.IsExternal(e));
        var dns = r.Events.Count(e => e.Action == EventAction.DnsQuery);
        var procs = r.AllProcesses.Count(p => p.InAnalyzedTree);
        var scripts = r.AllProcesses.Count(p => p.InAnalyzedTree && p.Name.ToLowerInvariant() is "powershell.exe" or "cmd.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe" or "pwsh.exe");
        var sig = r.Static?.Signature;
        Summary.Add(new(Loc.T("FileReputation"), Loc.T("ReputationLocalOnly"), Severity.Informational));
        Summary.Add(new(Loc.T("DigitalSignature"), sig?.Status switch
        {
            SignatureStatus.Valid => Loc.F("SignedBy", sig.Publisher ?? "?"),
            SignatureStatus.Invalid => Loc.T("SignatureInvalid"),
            SignatureStatus.PresentUnverified => Loc.T("SignatureUnverified"),
            _ => Loc.T("SignatureNone"),
        }, sig?.Status switch { SignatureStatus.Valid => Severity.Informational, SignatureStatus.Invalid => Severity.High, _ => Severity.Low }));
        Summary.Add(new(Loc.T("Persistence"), persist == 0 ? Loc.T("NoneObserved") : Loc.F("MechanismsCount", persist), persist == 0 ? Severity.Informational : Severity.High));
        Summary.Add(new(Loc.T("NetworkActivity"), external + dns == 0 ? Loc.T("NoneObserved") : Loc.F("NetworkSummary", external, dns), external > 0 ? Severity.Medium : dns > 0 ? Severity.Low : Severity.Informational));
        Summary.Add(new(Loc.T("ProcessBehavior"), Loc.F("ProcessSummary", procs, scripts), scripts > 0 ? Severity.Low : Severity.Informational));
        Summary.Add(new(Loc.T("SystemChanges"), r.SystemChanges is { } sc ? Loc.F("ChangesCount", sc.TotalChanges) : Loc.T("NoSnapshot"), r.SystemChanges is { TotalChanges: > 0 } ? Severity.Low : Severity.Informational));

        Contributions.Clear();
        foreach (var c in r.Risk.Contributions) Contributions.Add(new ContributionRow($"+{c.Points}", c.Title.Get(lang), c.Capped));
        Findings.Clear();
        foreach (var f in r.Findings) Findings.Add(new FindingItem(f));
        Chains.Clear();
        foreach (var c in r.Chains) Chains.Add(new ChainItem(c));

        ApplyTimelineFilter();
        BuildProcessTree();

        // Files
        var executedImages = new HashSet<string>(r.AllProcesses.Where(p => p.ImageDroppedDuringAnalysis && p.ImagePath is not null).Select(p => p.ImagePath!), StringComparer.OrdinalIgnoreCase);
        _allFiles = r.Events.Where(e => e.Category == EventCategory.File).Select(e => new FileRow(e, false))
            .Concat(r.Events.Where(e => e.Action == EventAction.ProcessStart && e.Detail(DetailKeys.ImagePath) is { } img && executedImages.Contains(img))
                .Select(e => new FileRow(e with { Target = e.Detail(DetailKeys.ImagePath) }, true)))
            .OrderBy(f => f.Event.RelativeTime).ToList();
        ApplyFileFilter();

        _allRegistry = r.Events.Where(e => e.Category == EventCategory.Registry).Select(e => new RegistryRow(e, PersistenceCatalog.IsSensitiveLocation(e))).ToList();
        ApplyRegistryFilter();

        // Network
        var map = NetworkMap.Build(r.Events);
        Dns.Clear();
        foreach (var e in r.Events.Where(e => e.Action == EventAction.DnsQuery)) Dns.Add(new DnsRow(e));
        Connections.Clear();
        foreach (var e in r.Events.Where(e => e.Action is EventAction.NetworkConnect or EventAction.NetworkSend)) Connections.Add(new ConnectionRow(e, map.DomainFor(e.Detail(DetailKeys.RemoteAddress))));
        NetworkTree.Clear();
        foreach (var byProcess in r.Events.Where(e => e.Action is EventAction.NetworkConnect or EventAction.DnsQuery).GroupBy(e => e.ProcessName))
        {
            var domains = new List<NetworkTreeNode>();
            var connects = byProcess.Where(e => e.Action == EventAction.NetworkConnect).ToList();
            foreach (var q in byProcess.Where(e => e.Action == EventAction.DnsQuery).GroupBy(e => e.Detail(DetailKeys.QueryName) ?? e.Target ?? "?"))
            {
                var endpoints = connects.Where(c => string.Equals(map.DomainFor(c.Detail(DetailKeys.RemoteAddress)), q.Key, StringComparison.OrdinalIgnoreCase))
                    .Select(NetworkMap.Endpoint).Distinct().Select(ep => new NetworkTreeNode(ep, null, [], 2)).ToList();
                domains.Add(new NetworkTreeNode(q.Key, endpoints.Count == 0 ? Loc.T("LookupOnly") : null, endpoints, 1));
            }
            foreach (var c in connects.Where(c => map.DomainFor(c.Detail(DetailKeys.RemoteAddress)) is null).Select(NetworkMap.Endpoint).Distinct())
                domains.Add(new NetworkTreeNode(c, Loc.T("DirectIp"), [], 1));
            NetworkTree.Add(new NetworkTreeNode(byProcess.Key, null, domains, 0));
        }

        Persistence.Clear();
        foreach (var p in r.Persistence.OrderByDescending(p => p.ByAnalyzedTree || p.PointsToDroppedFile).ThenBy(p => p.Time)) Persistence.Add(new PersistenceItem(p));

        Indicators.Clear();
        foreach (var g in r.Indicators.GroupBy(i => i.Type)) Indicators.Add(new IndicatorGroup(g.Key, g));

        BuildChanges();

        RawEvents.Clear();
        _rawOffset = 0;
        _ = LoadMoreRawAsync();

        Chat.Clear();
        Suggestions.Clear();
        foreach (var s in AskBlazma.SuggestedQuestions(lang)) Suggestions.Add(s);
        SelectedFinding = null;

        foreach (var name in new[] { nameof(FileName), nameof(Score), nameof(Verdict), nameof(VerdictText), nameof(IsDemo), nameof(IsFailed), nameof(FailureReason),
                     nameof(MonitoringInterrupted), nameof(Sha256), nameof(MetaLine), nameof(Disclaimer), nameof(NoiseNote), nameof(HasNoiseNote), nameof(HasFindings),
                     nameof(HasNoFindings), nameof(HasChains), nameof(HasPersistence), nameof(HasNoPersistence), nameof(HasChanges), nameof(HasNoChanges), nameof(HasNoNetwork) })
            OnPropertyChanged(name);
    }

    private void BuildChanges()
    {
        ChangeTiles.Clear();
        ChangeGroups.Clear();
        if (Result?.SystemChanges is not { } sc) return;
        ChangeTiles.Add(new(Loc.T("Files"), $"+ {sc.FilesCreated.Count} {Loc.T("Created")}", $"~ {sc.FilesModified.Count} {Loc.T("Modified")}", $"− {sc.FilesDeleted.Count} {Loc.T("DeletedLower")}"));
        ChangeTiles.Add(new(Loc.T("CatRegistry"), $"+ {sc.RegistryAdded.Count} {Loc.T("KeysValues")}", $"~ {sc.RegistryModified.Count} {Loc.T("Modified")}", $"− {sc.RegistryRemoved.Count} {Loc.T("Removed")}"));
        ChangeTiles.Add(new(Loc.T("Services"), $"+ {sc.ServicesAdded.Count}", $"− {sc.ServicesRemoved.Count}", string.Empty));
        ChangeTiles.Add(new(Loc.T("ScheduledTasks"), $"+ {sc.TasksAdded.Count}", $"− {sc.TasksRemoved.Count}", string.Empty));
        ChangeTiles.Add(new(Loc.T("Startup"), $"+ {sc.StartupAdded.Count}", $"− {sc.StartupRemoved.Count}", string.Empty));
        ChangeGroups.Add(new(Loc.T("FilesCreated"), sc.FilesCreated.Select(f => "+ " + f.Path).ToList()));
        ChangeGroups.Add(new(Loc.T("FilesModified"), sc.FilesModified.Select(f => $"~ {f.Path}  ({f.OldSize} → {f.NewSize} B)").ToList()));
        ChangeGroups.Add(new(Loc.T("FilesDeleted"), sc.FilesDeleted.Select(f => "− " + f.Path).ToList()));
        ChangeGroups.Add(new(Loc.T("RegistryChanges"), sc.RegistryAdded.Select(x => $"+ {x.Key}\\{x.ValueName} = {x.NewData}")
            .Concat(sc.RegistryModified.Select(x => $"~ {x.Key}\\{x.ValueName}: {x.OldData} → {x.NewData}"))
            .Concat(sc.RegistryRemoved.Select(x => $"− {x.Key}\\{x.ValueName}")).ToList()));
        ChangeGroups.Add(new(Loc.T("ServicesTasksStartup"), sc.ServicesAdded.Select(s => "+ " + Loc.T("Service") + ": " + s)
            .Concat(sc.TasksAdded.Select(t => "+ " + Loc.T("Task") + ": " + t))
            .Concat(sc.StartupAdded.Select(s => "+ " + Loc.T("Startup") + ": " + s)).ToList()));
    }

    private void BuildProcessTree()
    {
        ProcessRoots.Clear();
        if (Result is null) return;
        var roots = Result.ProcessRoots.Where(n => ShowBackgroundProcesses || n.SelfAndDescendants().Any(x => x.InAnalyzedTree)).ToList();
        foreach (var root in roots) ProcessRoots.Add(new ProcessItem(root, ShowBackgroundProcesses));
        SelectedProcess = ProcessRoots.FirstOrDefault();
    }

    private void BuildProcessDetails()
    {
        ProcessDetails.Clear();
        ProcessActivity.Clear();
        if (SelectedProcess?.Node is not { } n || Result is null) return;
        var parent = n.ParentKey is { } pk ? Result.AllProcesses.FirstOrDefault(p => p.Key == pk) : null;
        ProcessDetails.Add(new("PID", n.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture), true));
        ProcessDetails.Add(new("PPID", parent is null ? n.ParentPid.ToString(System.Globalization.CultureInfo.InvariantCulture) : $"{n.ParentPid} ({parent.Name})", true));
        ProcessDetails.Add(new(Loc.T("ImagePath"), n.ImagePath ?? "—", true));
        ProcessDetails.Add(new(Loc.T("CommandLine"), n.CommandLine ?? "—", true));
        ProcessDetails.Add(new(Loc.T("StartTime"), Fmt.Relative(n.Start), true));
        ProcessDetails.Add(new(Loc.T("EndTime"), n.End is { } end ? Fmt.Relative(end) + (n.ExitCode is { } code ? $" (exit {code})" : string.Empty) : Loc.T("StillRunning"), true));
        ProcessDetails.Add(new(Loc.T("IntegrityLevel"), n.IntegrityLevel ?? "—"));
        ProcessDetails.Add(new(Loc.T("User"), n.User ?? "—"));
        ProcessDetails.Add(new(Loc.T("Architecture"), n.Architecture ?? "—"));
        ProcessDetails.Add(new(Loc.T("Signature"), n.Signer ?? Loc.T("NotReported")));
        ProcessDetails.Add(new("SHA-256", n.Sha256 ?? "—", true));
        var mine = ActivityOf(n).ToList();
        ProcessDetails.Add(new(Loc.T("Children"), n.Children.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        ProcessDetails.Add(new(Loc.T("FilesTouched"), mine.Count(e => e.Category == EventCategory.File).ToString(System.Globalization.CultureInfo.InvariantCulture)));
        ProcessDetails.Add(new(Loc.T("RegistryActivity"), mine.Count(e => e.Category == EventCategory.Registry).ToString(System.Globalization.CultureInfo.InvariantCulture)));
        ProcessDetails.Add(new(Loc.T("NetworkActivity"), mine.Count(e => e.Category is EventCategory.Network or EventCategory.Dns).ToString(System.Globalization.CultureInfo.InvariantCulture)));
        foreach (var e in mine.Take(300)) ProcessActivity.Add(new TimelineRow(e));
    }

    private IEnumerable<AnalysisEvent> ActivityOf(ProcessNode n) =>
        Result!.Events.Where(e => e.ProcessId == n.Pid && e.RelativeTime >= n.Start && (n.End is null || e.RelativeTime <= n.End.Value + TimeSpan.FromMilliseconds(1)));

    private void OnChipToggled(object? sender, EventArgs e)
    {
        var chip = (FilterChip)sender!;
        if (chip.Key == "All" && chip.IsChecked)
            foreach (var c in CategoryChips.Where(c => c.Key != "All")) c.SetSilently(false);
        else if (chip.Key != "All" && chip.IsChecked)
            CategoryChips[0].SetSilently(false);
        if (!CategoryChips.Any(c => c.IsChecked)) CategoryChips[0].SetSilently(true);
        ApplyTimelineFilter();
    }

    private static void ExclusiveChip(ObservableCollection<FilterChip> chips, FilterChip chosen)
    {
        if (!chosen.IsChecked) { if (!chips.Any(c => c.IsChecked)) chips[0].SetSilently(true); return; }
        foreach (var c in chips.Where(c => c != chosen)) c.SetSilently(false);
    }

    private void ApplyTimelineFilter()
    {
        if (Result is null) return;
        var cats = CategoryChips.Where(c => c.IsChecked && c.Key != "All").Select(c => Enum.Parse<EventCategory>(c.Key)).ToHashSet();
        if (cats.Contains(EventCategory.Network)) cats.Add(EventCategory.Dns);
        var text = TimelineSearch.Trim();
        var minSeverity = MinSeverity?.Value ?? Severity.Informational;
        var proc = ProcessFilter == Loc.T("AllProcesses") ? null : ProcessFilter;
        TimeSpan? from = double.TryParse(FromSeconds, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var f) ? TimeSpan.FromSeconds(f) : null;
        TimeSpan? to = double.TryParse(ToSeconds, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var t) ? TimeSpan.FromSeconds(t) : null;

        var rows = _allTimeline.Where(r =>
            (cats.Count == 0 || cats.Contains(r.Event.Category)) &&
            r.Event.Severity >= minSeverity &&
            (proc is null || r.Event.ProcessName.Equals(proc, StringComparison.OrdinalIgnoreCase)) &&
            (from is null || r.Event.RelativeTime >= from) &&
            (to is null || r.Event.RelativeTime <= to) &&
            (text.Length == 0 || r.Process.Contains(text, StringComparison.OrdinalIgnoreCase) || r.Target.Contains(text, StringComparison.OrdinalIgnoreCase)
                || r.Event.Details.Values.Any(v => v.Contains(text, StringComparison.OrdinalIgnoreCase))));
        if (_highlight.Count > 0) rows = rows.Select(r => _highlight.Contains(r.Sequence) ? new TimelineRow(r.Event) { Highlight = true } : r);

        Timeline.Clear();
        foreach (var r in rows) Timeline.Add(r);
        TimelineCount = Loc.F("ShowingEvents", Timeline.Count, _allTimeline.Count);
    }

    private void ApplyFileFilter()
    {
        var kind = FileChips.FirstOrDefault(c => c.IsChecked)?.Key ?? "All";
        var text = FileSearch.Trim();
        Files.Clear();
        foreach (var f in _allFiles.Where(f => (kind == "All" || f.Kind == kind) && (text.Length == 0 || f.Path.Contains(text, StringComparison.OrdinalIgnoreCase) || f.Process.Contains(text, StringComparison.OrdinalIgnoreCase))))
            Files.Add(f);
    }

    private void ApplyRegistryFilter()
    {
        var text = RegistrySearch.Trim();
        Registry.Clear();
        foreach (var r in _allRegistry.Where(r => (!RegistryPersistenceOnly || r.Sensitive) && (text.Length == 0 || r.Key.Contains(text, StringComparison.OrdinalIgnoreCase) || r.ValueLine.Contains(text, StringComparison.OrdinalIgnoreCase) || r.Process.Contains(text, StringComparison.OrdinalIgnoreCase))))
            Registry.Add(r);
    }

    public void ShowSequencesInTimeline(IEnumerable<long> sequences)
    {
        _highlight = sequences.ToHashSet();
        TimelineSearch = string.Empty;
        foreach (var c in CategoryChips) c.SetSilently(c.Key == "All");
        MinSeverity = SeverityOptions.FirstOrDefault();
        ProcessFilter = ProcessNames.FirstOrDefault();
        FromSeconds = ToSeconds = string.Empty;
        ApplyTimelineFilter();
        SelectedTab = 1;
        var first = Timeline.FirstOrDefault(r => r.Highlight);
        if (first is not null) Dispatcher.UIThread.Post(() => ScrollTimelineTo?.Invoke(this, first), DispatcherPriority.Background);
    }

    [RelayCommand] private void ClearHighlight() { _highlight = []; ApplyTimelineFilter(); }
    [RelayCommand] private void SelectFinding(FindingItem? item) => SelectedFinding = item;
    [RelayCommand] private void CloseFinding() => SelectedFinding = null;
    [RelayCommand] private void FindingInTimeline() { if (SelectedFinding is { } f) ShowSequencesInTimeline(f.Finding.AllEventSequences); }

    [RelayCommand]
    private void FindingProcess()
    {
        if (SelectedFinding?.Finding.Processes.FirstOrDefault() is not { } key) return;
        SelectedTab = 2;
        SelectedProcess = Flatten(ProcessRoots).FirstOrDefault(p => p.Node.Key == key);
    }

    [RelayCommand] private void ProcessInTimeline() { if (SelectedProcess?.Node is { } n) ShowSequencesInTimeline(ActivityOf(n).Select(e => e.Sequence).Append(n.StartEventSequence)); }
    [RelayCommand] private void PartInTimeline(ChatPart? part) { if (part is { Events: > 0 }) ShowSequencesInTimeline(part.Sequences); }

    private static IEnumerable<ProcessItem> Flatten(IEnumerable<ProcessItem> items) => items.SelectMany(i => Flatten(i.Children).Prepend(i));

    [RelayCommand]
    private async Task LoadMoreRawAsync()
    {
        if (Result is null) return;
        var page = await _repository.QueryEventsAsync(new EventQuery { AnalysisId = Result.AnalysisId, Offset = _rawOffset, Limit = 1000 }, CancellationToken.None);
        foreach (var e in page) RawEvents.Add(new TimelineRow(e));
        _rawOffset += page.Count;
        HasMoreRaw = page.Count == 1000;
    }

    [RelayCommand]
    private void Ask(string? text)
    {
        var q = (text ?? Question).Trim();
        if (q.Length == 0 || Result is null) return;
        Chat.Add(new ChatMessage { FromUser = true, Text = q });
        var answer = _ask.Ask(Result, q, Loc.Instance.Code);
        Chat.Add(new ChatMessage { FromUser = false, Text = answer.Text, Parts = answer.Parts.Select(p => new ChatPart(p)).ToList() });
        Question = string.Empty;
    }

    [RelayCommand] private Task ExportHtml() => Result is null ? Task.CompletedTask : _export.ExportAsync(Result, Core.Settings.ReportFormat.Html);
    [RelayCommand] private Task ExportJson() => Result is null ? Task.CompletedTask : _export.ExportAsync(Result, Core.Settings.ReportFormat.Json);
    [RelayCommand] private Task ExportIndicators() => Result is null ? Task.CompletedTask : _export.ExportIndicatorsAsync(Result);
    [RelayCommand] private Task CopyHash() => _main.CopyAsync(Sha256);
    [RelayCommand] private Task CopyValue(string? value) => _main.CopyAsync(value ?? string.Empty);
    [RelayCommand] private void Compare() { if (Result is not null) _main.OpenCompare(Result.AnalysisId); }
    [RelayCommand] private void Back() => _main.Navigate("History");

    protected override void OnLanguageChanged()
    {
        if (Result is null) return;
        var tab = SelectedTab;
        foreach (var c in CategoryChips.Concat(FileChips)) c.Refresh();
        Build();
        SelectedTab = tab;
    }
}

public sealed record SeverityOption(Severity Value)
{
    public string Label => Value == Severity.Informational ? Loc.T("AnySeverity") : Fmt.Severity(Value) + "+";
    public override string ToString() => Label;
}
