using System.Collections.ObjectModel;
using Blazma.Analysis.Engine;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Indicators;
using Blazma.Core.Processes;
using Blazma.Intelligence;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Blazma.App.ViewModels;

public sealed record SummaryRow(string Label, string Value, Severity Level);

public sealed record ContributionRow(string Points, string Title, bool Capped);

public sealed record EvidenceRow(string Description, string? Technical, int EventCount)
{
    public bool HasTechnical => !string.IsNullOrEmpty(Technical);
}

public sealed class FindingItem(Finding f)
{
    public Finding Finding { get; } = f;
    public string Title => Finding.Title.Get(Loc.Instance.Code);
    public string Explanation => Finding.Explanation.Get(Loc.Instance.Code);
    public Severity Severity => Finding.Severity;
    public string Points => "+" + Finding.Points;
    public string RuleId => Finding.RuleId;
    public string Attack => Finding.AttackTechniques.Count == 0 ? string.Empty : "ATT&CK " + string.Join(", ", Finding.AttackTechniques);
    public bool HasAttack => Finding.AttackTechniques.Count > 0;
    public string Category => Fmt.FindingCategory(Finding.Category);
    public string FirstSeen => Finding.FirstSeen is { } t ? Fmt.Relative(t) : "—";
    public string Provenance => Loc.T("Prov" + Finding.Provenance);
    public int RelatedEvents => Finding.AllEventSequences.Count();
    public int RelatedProcesses => Finding.Processes.Count;
    public IReadOnlyList<EvidenceRow> Evidence => Finding.Evidence.Select(e => new EvidenceRow(e.Description.Get(Loc.Instance.Code), e.Technical, e.EventSequences.Count)).ToList();
}

public sealed class ChainItem(BehaviorChain c)
{
    public BehaviorChain Chain { get; } = c;
    public string Title => Chain.Title.Get(Loc.Instance.Code);
    public Severity Severity => Chain.Severity;
    public IReadOnlyList<ChainStepRow> Steps => Chain.Steps.Select((s, i) => new ChainStepRow(s, i == Chain.Steps.Count - 1)).ToList();
}

public sealed class ChainStepRow(ChainStep s, bool last)
{
    public ChainStep Step { get; } = s;
    public string Kind => Loc.T("Step" + Step.Kind);
    public string Text => Step.Kind switch
    {
        ChainStepKind.Started => Step.Actor,
        ChainStepKind.Spawned or ChainStepKind.Executed => $"{Step.Actor} → {Step.Target}",
        _ => $"{Step.Actor}: {Step.Target}",
    };
    public string Time => Fmt.Relative(Step.Time);
    public bool ShowArrow => !last;
}

public sealed partial class ProcessItem : ObservableObject
{
    public ProcessItem(ProcessNode node, bool includeBackground)
    {
        Node = node;
        Children = new ObservableCollection<ProcessItem>(node.Children.Where(c => includeBackground || c.SelfAndDescendants().Any(x => x.InAnalyzedTree)).Select(c => new ProcessItem(c, includeBackground)));
    }

    public ProcessNode Node { get; }
    public ObservableCollection<ProcessItem> Children { get; }
    public string Name => Node.Name;
    public string Pid => "PID " + Node.Pid;
    public bool IsSample => Node.IsSample;
    public bool IsDropped => Node.ImageDroppedDuringAnalysis;
    public bool IsBackground => !Node.InAnalyzedTree;
    public string Start => Fmt.Relative(Node.Start);
    [ObservableProperty] private bool _isExpanded = true;
}

public sealed record DetailRow(string Label, string Value, bool Mono = false);

public sealed class FileRow(AnalysisEvent e, bool executed)
{
    public AnalysisEvent Event { get; } = e;
    public string Action => executed ? Loc.T("FileExecuted") : Fmt.Action(Event.Action);
    public string Path => Event.Action == EventAction.FileRename ? $"{Event.Target} → {Event.Detail(DetailKeys.NewPath)}" : Event.Target ?? string.Empty;
    public string Process => Event.ProcessName;
    public string Time => Fmt.Relative(Event.RelativeTime);
    public string Type => System.IO.Path.GetExtension(Event.Target ?? string.Empty).TrimStart('.').ToUpperInvariant();
    public string Extra => string.Join("  ", new[] { Event.Detail(DetailKeys.Size) is { } s && long.TryParse(s, out var n) ? Fmt.Size(n) : null, Event.Detail(DetailKeys.Sha256) is { } h ? "SHA-256 " + Fmt.ShortHash(h) : null }.Where(x => x is not null));
    public bool Executed => executed;
    public string Kind => executed ? "Executed" : Event.Action.ToString();
}

public sealed class RegistryRow(AnalysisEvent e, bool sensitive)
{
    public AnalysisEvent Event { get; } = e;
    public string Action => Fmt.Action(Event.Action);
    public string Key => Event.Target ?? string.Empty;
    public string ValueName => Event.Detail(DetailKeys.ValueName) ?? string.Empty;
    public string Data => Event.Detail(DetailKeys.ValueData) ?? string.Empty;
    public string OldData => Event.Detail(DetailKeys.OldValue) ?? string.Empty;
    public string Process => Event.ProcessName;
    public string Time => Fmt.Relative(Event.RelativeTime);
    public bool Sensitive => sensitive;
    public bool HasValue => ValueName.Length > 0 || Data.Length > 0;
    public string ValueLine => Data.Length == 0 ? ValueName : $"{ValueName} = {Data}";
}

public sealed class DnsRow(AnalysisEvent e)
{
    public AnalysisEvent Event { get; } = e;
    public string Domain => Event.Detail(DetailKeys.QueryName) ?? Event.Target ?? "?";
    public string Result => Event.Detail(DetailKeys.QueryResult) ?? Loc.T("NoAnswer");
    public string Process => Event.ProcessName;
    public string Time => Fmt.Relative(Event.RelativeTime);
}

public sealed class ConnectionRow(AnalysisEvent e, string? domain)
{
    public AnalysisEvent Event { get; } = e;
    public string Address => Event.Detail(DetailKeys.RemoteAddress) ?? Event.Target ?? "?";
    public string Port => Event.Detail(DetailKeys.RemotePort) ?? "—";
    public string Protocol => Event.Detail(DetailKeys.Protocol) ?? "TCP";
    public string Domain => domain ?? "—";
    public string Process => Event.ProcessName;
    public string Time => Fmt.Relative(Event.RelativeTime);
    public bool External => NetworkMap.IsExternal(Event);
    public string Bytes => Event.Detail(DetailKeys.BytesSent) is { } s ? $"↑{s} ↓{Event.Detail(DetailKeys.BytesReceived) ?? "0"}" : string.Empty;
}

public sealed record NetworkTreeNode(string Text, string? Sub, IReadOnlyList<NetworkTreeNode> Children, int Depth);

public sealed class PersistenceItem(PersistenceDetection p)
{
    public PersistenceDetection Detection { get; } = p;
    public string Title => PersistenceNames.Of(Detection.Technique).Get(Loc.Instance.Code);
    public string Explanation => Detection.Explanation.Get(Loc.Instance.Code);
    public string Target => Detection.Target;
    public string? Value => Detection.Value;
    public bool HasValue => !string.IsNullOrEmpty(Value);
    public string Process => Detection.ProcessName;
    public string Time => Fmt.Relative(Detection.Time);
    public Severity Severity => Detection.Severity;
    public string Attribution => Detection.ByAnalyzedTree ? Loc.T("ByAnalyzedProgram") : Loc.T("BySystemProcess");
    public bool PointsToDrop => Detection.PointsToDroppedFile;
}

public sealed class IndicatorGroup(IndicatorType type, IEnumerable<Indicator> items)
{
    public string Title => Fmt.IndicatorType(type);
    public IReadOnlyList<IndicatorItem> Items { get; } = items.Select(i => new IndicatorItem(i)).ToList();
    public int Count => Items.Count;
}

public sealed class IndicatorItem(Indicator i)
{
    public Indicator Indicator { get; } = i;
    public string Value => Indicator.Value;
    public IndicatorStatus Status => Indicator.Status;
    public string Source => Indicator.Source;
    public int Events => Indicator.EventSequences.Count;
}

public sealed record ChangeTile(string Title, string Line1, string Line2, string Line3);

public sealed record ChangeGroup(string Title, IReadOnlyList<string> Lines)
{
    public int Count => Lines.Count;
}

public sealed class ChatMessage
{
    public required bool FromUser { get; init; }
    public required string Text { get; init; }
    public IReadOnlyList<ChatPart> Parts { get; init; } = [];
}

public sealed class ChatPart(AnswerPart p)
{
    public string Text { get; } = p.Text;
    public string Label { get; } = Loc.T("Prov" + p.Provenance);
    public bool IsInference { get; } = p.Provenance != Provenance.ObservedFact;
    public int Events { get; } = p.EventSequences.Count;
    public IReadOnlyList<long> Sequences { get; } = p.EventSequences;
    public string Citation => Events > 0 ? Loc.F("CitesEvents", Events) : string.Empty;
    public bool HasCitation => Events > 0;
}

public sealed class FilterChip(string key, string labelKey, bool isChecked = false) : ObservableObject
{
    private bool _isChecked = isChecked;
    public string Key { get; } = key;
    public string Label => Loc.T(labelKey);
    public bool IsChecked { get => _isChecked; set { if (SetProperty(ref _isChecked, value)) Toggled?.Invoke(this, EventArgs.Empty); } }
    public event EventHandler? Toggled;
    public void Refresh() => OnPropertyChanged(nameof(Label));
    public void SetSilently(bool value) { _isChecked = value; OnPropertyChanged(nameof(IsChecked)); }
}
