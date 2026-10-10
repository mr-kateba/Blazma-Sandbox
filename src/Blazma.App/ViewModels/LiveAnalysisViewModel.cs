using System.Collections.ObjectModel;
using Avalonia.Threading;
using Blazma.Analysis.Pipeline;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Blazma.App.ViewModels;

public enum StepState { Pending, Active, Done, Failed }

public sealed partial class StageStep(string key, AnalysisStage[] stages) : ObservableObject
{
    public string Key { get; } = key;
    public AnalysisStage[] Stages { get; } = stages;
    public string Title => Loc.T(Key);
    [ObservableProperty] private StepState _state;
    public bool IsDone => State == StepState.Done;
    public bool IsActive => State == StepState.Active;
    public bool IsPending => State == StepState.Pending;
    public bool IsFailed => State == StepState.Failed;
    partial void OnStateChanged(StepState value)
    {
        OnPropertyChanged(nameof(IsDone)); OnPropertyChanged(nameof(IsActive)); OnPropertyChanged(nameof(IsPending)); OnPropertyChanged(nameof(IsFailed));
    }
    public void Refresh() => OnPropertyChanged(nameof(Title));
}

/// <summary>One line of the live (and report) timeline.</summary>
public sealed class TimelineRow(AnalysisEvent e)
{
    public AnalysisEvent Event { get; } = e;
    public long Sequence => Event.Sequence;
    public string Time => Fmt.Relative(Event.RelativeTime);
    public string Category => Fmt.Category(Event.Category).ToUpperInvariant();
    public string Action => Fmt.Action(Event.Action);
    public string Process => Event.ProcessName;
    public string Pid => Event.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
    public string Target => Event.Target ?? Event.Detail(DetailKeys.CommandLine) ?? Event.Detail(DetailKeys.Reason) ?? string.Empty;
    public Severity Severity => Event.Severity;
    public bool Highlight { get; init; }
    public string CategoryKey => Event.Category.ToString();
}

public sealed partial class LiveAnalysisViewModel : PageViewModel
{
    private readonly MainViewModel _main;
    private readonly ToastService _toasts;
    private readonly DispatcherTimer _timer;
    private ActiveAnalysis? _active;
    private DateTimeOffset _startedAt;
    private const int MaxLiveRows = 50_000;
    private const int ScreenPreviewWidth = 640;

    public LiveAnalysisViewModel(MainViewModel main, ToastService toasts)
    {
        _main = main;
        _toasts = toasts;
        _timer = new DispatcherTimer(TimeSpan.FromMilliseconds(150), DispatcherPriority.Background, (_, _) => Drain());
        Steps =
        [
            new StageStep("StepPreparing", [AnalysisStage.Preparing, AnalysisStage.CreatingSandbox]),
            new StageStep("StepStarting", [AnalysisStage.Booting]),
            new StageStep("StepDeploying", [AnalysisStage.DeployingAgent, AnalysisStage.Ready]),
            new StageStep("StepTransferring", [AnalysisStage.TransferringSample]),
            new StageStep("StepExecuting", [AnalysisStage.Analyzing]),
            new StageStep("StepCollecting", [AnalysisStage.CollectingEvents, AnalysisStage.Finalizing]),
            new StageStep("StepReport", [AnalysisStage.GeneratingReport]),
        ];
    }

    public override string NavKey => "NewAnalysis";

    public ObservableCollection<StageStep> Steps { get; }
    public ObservableCollection<TimelineRow> Events { get; } = [];

    [ObservableProperty] private string _fileName = string.Empty;
    [ObservableProperty] private string _elapsed = "00:00";
    [ObservableProperty] private string _stageText = string.Empty;
    [ObservableProperty] private int _eventCount;
    [ObservableProperty] private int _processCount;
    [ObservableProperty] private int _connectionCount;
    [ObservableProperty] private int _liveScore;
    [ObservableProperty] private Verdict _liveVerdict;
    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private bool _isDone;
    [ObservableProperty] private bool _isFailed;
    [ObservableProperty] private bool _isDemo;
    [ObservableProperty] private bool _autoScroll = true;
    [ObservableProperty] private bool _monitoringInterrupted;
    [ObservableProperty] private string? _failureReason;
    [ObservableProperty] private Guid? _resultId;
    [ObservableProperty] private double _progress;
    [ObservableProperty] private Avalonia.Media.Imaging.Bitmap? _screen;
    [ObservableProperty] private bool _canControl;
    private string? _screenPath;

    public bool HasScreen => Screen is not null;
    partial void OnScreenChanged(Avalonia.Media.Imaging.Bitmap? oldValue, Avalonia.Media.Imaging.Bitmap? newValue)
    {
        oldValue?.Dispose();
        OnPropertyChanged(nameof(HasScreen));
    }

    public event EventHandler? RowsAdded;

    public void Attach(ActiveAnalysis active)
    {
        _active = active;
        _startedAt = DateTimeOffset.Now;
        FileName = active.FileName;
        IsDemo = active.IsDemo;
        Events.Clear();
        EventCount = ProcessCount = ConnectionCount = LiveScore = 0;
        LiveVerdict = Verdict.LowRisk;
        IsRunning = true; IsDone = false; IsFailed = false; FailureReason = null; ResultId = null; MonitoringInterrupted = false;
        Screen = null; _screenPath = null; CanControl = false;
        foreach (var s in Steps) s.State = StepState.Pending;
        // Raised on the UI thread; a late update from an earlier run is ignored.
        active.Progress += (_, p) => { if (ReferenceEquals(_active, active)) OnProgress(p); };
        _timer.Start();
        _ = WatchAsync(active);
    }

    private async Task WatchAsync(ActiveAnalysis active)
    {
        AnalysisResult result;
        try
        {
            result = await active.Completion;
        }
        catch (Exception ex)
        {
            _timer.Stop();
            await Dispatcher.UIThread.InvokeAsync(() => ShowFailureAsync(active, ex));
            return;
        }

        _timer.Stop();
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            Drain();
            IsRunning = false; IsDone = true; ResultId = result.AnalysisId;
            LiveScore = result.Risk.Score; LiveVerdict = result.Risk.Verdict;
            foreach (var s in Steps) s.State = StepState.Done;
            Progress = 100;
            _toasts.AnalysisCompleted(result.Sample.FileName, result.Risk.Score);
            if (result.Risk.Verdict >= Verdict.HighRiskBehavior) _toasts.HighRisk(result.Sample.FileName);
        });
        await Task.Delay(900);
        // The analysis is saved by now. A report that cannot be opened is shown as that problem,
        // never as a failed analysis with a Retry that would run the sample again.
        await Dispatcher.UIThread.InvokeAsync(() => _main.SafeAsync(() => _main.OpenReportAsync(result.AnalysisId)));
    }

    private async Task ShowFailureAsync(ActiveAnalysis active, Exception ex)
    {
        IsRunning = false;
        // Anything that ends a run the user cancelled is a cancellation, not an error to retry.
        if (ex is OperationCanceledException || active.Cancellation.IsCancellationRequested)
        {
            FailureReason = Loc.T("AnalysisCancelled");
            MarkFailed();
            return;
        }
        var reason = FailureText(ex);
        FailureReason = reason;
        MarkFailed();
        _toasts.AnalysisFailed(reason);
        var choice = await _main.Dialogs.ErrorAsync(Loc.T("EnvironmentFailedTitle"), reason, Diagnostics(ex), canRetry: true);
        if (choice == "retry") await _main.SafeAsync(_main.RetryLastAsync);
    }

    /// <summary>
    /// The reason shown to the user: a short explanation in the current language, then the
    /// technical reason from the analysis (which is in English).
    /// </summary>
    internal static string FailureText(Exception ex)
    {
        var reason = ex is AnalysisFailedException af ? af.Reason : ex.Message;
        var cause = ex is AnalysisFailedException { InnerException: { } inner } ? inner.GetBaseException() : ex.GetBaseException();
        var hint = cause switch
        {
            UnauthorizedAccessException => "AnalysisErrorAccess",
            IOException => "AnalysisErrorFiles",
            System.Text.Json.JsonException => "AnalysisErrorData",
            System.Data.Common.DbException => "AnalysisErrorDatabase",
            OperationCanceledException or TimeoutException => "AnalysisErrorTimeout",
            AnalysisFailedException => "AnalysisErrorEnvironment",
            _ => "AnalysisErrorUnexpected",
        };
        return Loc.T(hint) + Environment.NewLine + reason;
    }

    private static string Diagnostics(Exception ex)
    {
        // Enough to troubleshoot, without file contents or personal data.
        var lines = new List<string>
        {
            $"Blazma Sandbox {typeof(LiveAnalysisViewModel).Assembly.GetName().Version?.ToString(3)}",
            $"OS: {Environment.OSVersion.VersionString} ({System.Runtime.InteropServices.RuntimeInformation.OSArchitecture})",
            $".NET: {Environment.Version}",
            $"Error: {ex.GetType().Name}",
        };
        for (var e = ex.InnerException; e is not null; e = e.InnerException) lines.Add($"Caused by: {e.GetType().Name}: {e.Message}");
        return string.Join(Environment.NewLine, lines);
    }

    private void MarkFailed()
    {
        IsFailed = true;
        foreach (var s in Steps.Where(s => s.State == StepState.Active)) s.State = StepState.Failed;
    }

    private void OnProgress(AnalysisProgress p)
    {
        StageText = Fmt.Stage(p.Stage);
        EventCount = p.EventCount;
        ProcessCount = p.ProcessCount;
        ConnectionCount = p.ConnectionCount;
        MonitoringInterrupted = p.MonitoringInterrupted;
        CanControl = p.CanControl;
        if (p.LatestScreenshot is { } shot && shot != _screenPath)
        {
            _screenPath = shot;
            _ = LoadScreenAsync(shot);
        }
        if (p.LiveScore is { } score) { LiveScore = score; LiveVerdict = p.LiveVerdict ?? Verdict.LowRisk; }
        var index = AnalysisStateMachine.IndexOf(p.Stage);
        if (index < 0) return;
        foreach (var step in Steps)
        {
            var max = step.Stages.Max(AnalysisStateMachine.IndexOf);
            var min = step.Stages.Min(AnalysisStateMachine.IndexOf);
            step.State = index > max ? StepState.Done : index >= min ? StepState.Active : StepState.Pending;
        }
        Progress = Math.Round(100.0 * index / (AnalysisStateMachine.Path.Count - 1));
    }

    /// <summary>
    /// Decodes the newest screenshot off the UI thread, scaled down to the preview size. The PNG was
    /// written by the host from validated raw pixels, never taken from the sandbox as-is. A file
    /// that cannot be read (still being written, locked by antivirus, damaged) is skipped; the next
    /// screenshot replaces it.
    /// </summary>
    private async Task LoadScreenAsync(string path)
    {
        Avalonia.Media.Imaging.Bitmap bitmap;
        try
        {
            bitmap = await Task.Run(() =>
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                return Avalonia.Media.Imaging.Bitmap.DecodeToWidth(stream, ScreenPreviewWidth);
            });
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return;
        }
        if (_screenPath == path) Screen = bitmap;
        else bitmap.Dispose();
    }

    private void Drain()
    {
        if (_active is null) return;
        Elapsed = Fmt.Relative(DateTimeOffset.Now - _startedAt, ms: false);
        var added = 0;
        while (added < 2000 && _active.Events.Reader.TryRead(out var e))
        {
            if (Events.Count < MaxLiveRows) Events.Add(new TimelineRow(e));
            added++;
        }
        if (added > 0) RowsAdded?.Invoke(this, EventArgs.Empty);
    }

    protected override void OnLanguageChanged()
    {
        foreach (var s in Steps) s.Refresh();
        if (_active?.Last is { } p) StageText = Fmt.Stage(p.Stage);
    }

    [RelayCommand]
    private async Task Cancel()
    {
        if (_active is null || !IsRunning) return;
        if (await _main.Dialogs.ConfirmAsync(Loc.T("CancelAnalysisTitle"), Loc.T("CancelAnalysisBody"), Loc.T("CancelAnalysis"), danger: true))
            await _active.Cancellation.CancelAsync();
    }

    [RelayCommand]
    private async Task ExtendRun()
    {
        if (_active is null || !CanControl) return;
        try { await _active.Control.ExtendAsync(TimeSpan.FromMinutes(2)); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { _toasts.Show(ToastKind.Warning, Loc.T("RunControlFailed"), ex.Message); return; }
        _toasts.Info(Loc.T("RunExtended"));
    }

    [RelayCommand]
    private async Task FinishRun()
    {
        if (_active is null || !CanControl) return;
        try { await _active.Control.FinishNowAsync(); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { _toasts.Show(ToastKind.Warning, Loc.T("RunControlFailed"), ex.Message); return; }
        _toasts.Info(Loc.T("RunFinishing"));
    }

    [RelayCommand] private Task OpenReport() => ResultId is { } id ? _main.OpenReportAsync(id) : Task.CompletedTask;
    [RelayCommand] private void BackToDashboard() => _main.Navigate("Dashboard");
}
