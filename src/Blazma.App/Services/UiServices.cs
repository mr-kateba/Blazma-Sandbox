using System.Collections.ObjectModel;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Blazma.App.Localization;
using Blazma.Core.Settings;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Blazma.App.Services;

public enum ToastKind { Info, Success, Warning, Error }

public sealed partial class Toast : ObservableObject
{
    public required ToastKind Kind { get; init; }
    public required string Title { get; init; }
    public string? Message { get; init; }
    public bool HasMessage => !string.IsNullOrEmpty(Message);
    public string Glyph => Kind switch { ToastKind.Success => "✓", ToastKind.Warning => "▲", ToastKind.Error => "✕", _ => "●" };
}

/// <summary>Short, non-blocking notices. Only the events the user cares about; never one per analysis event.</summary>
public sealed class ToastService(SettingsService settings)
{
    public ObservableCollection<Toast> Items { get; } = [];

    public void Show(ToastKind kind, string title, string? message = null)
    {
        Dispatcher.UIThread.Post(() =>
        {
            var toast = new Toast { Kind = kind, Title = title, Message = message };
            Items.Add(toast);
            while (Items.Count > 4) Items.RemoveAt(0);
            DispatcherTimer.RunOnce(() => Items.Remove(toast), TimeSpan.FromSeconds(Math.Clamp(settings.Current.Notifications.ToastSeconds, 2, 20)));
        });
    }

    public void Info(string title, string? message = null) => Show(ToastKind.Info, title, message);
    public void AnalysisCompleted(string file, int score) { if (settings.Current.Notifications.AnalysisCompleted) Show(ToastKind.Success, Loc.T("ToastAnalysisCompleted"), $"{file} · {score}/100"); }
    public void AnalysisFailed(string reason) { if (settings.Current.Notifications.AnalysisFailed) Show(ToastKind.Error, Loc.T("ToastAnalysisFailed"), reason); }
    public void HighRisk(string file) { if (settings.Current.Notifications.HighRiskDetected) Show(ToastKind.Warning, Loc.T("ToastHighRisk"), file); }
    public void Exported(string path) { if (settings.Current.Notifications.ReportExported) Show(ToastKind.Success, Loc.T("ToastExported"), Path.GetFileName(path)); }
}

public sealed partial class DialogButton(string label, string result, bool primary = false, bool danger = false) : ObservableObject
{
    public string Label { get; } = label;
    public string Result { get; } = result;
    public bool Primary { get; } = primary;
    public bool Danger { get; } = danger;
}

public sealed partial class DialogViewModel : ObservableObject
{
    private readonly TaskCompletionSource<string?> _tcs = new();
    public required string Title { get; init; }
    public required string Message { get; init; }
    public string? Details { get; init; }
    public string? DetailsLabel { get; init; }
    public bool IsError { get; init; }
    public required IReadOnlyList<DialogButton> Buttons { get; init; }
    public bool HasDetails => !string.IsNullOrEmpty(Details);

    [ObservableProperty] private bool _showDetails;

    public Task<string?> Result => _tcs.Task;

    [RelayCommand] private void Choose(string? result) => _tcs.TrySetResult(result);
    [RelayCommand] private void ToggleDetails() => ShowDetails = !ShowDetails;
    public void Cancel() => _tcs.TrySetResult(null);
}

/// <summary>In-window dialogs (no native message boxes) so they match Blazma and respect RTL.</summary>
public sealed partial class DialogService : ObservableObject
{
    [ObservableProperty] private DialogViewModel? _current;

    public async Task<string?> ShowAsync(DialogViewModel dialog)
    {
        Current = dialog;
        try { return await dialog.Result; }
        finally { if (Current == dialog) Current = null; }
    }

    public async Task<bool> ConfirmAsync(string title, string message, string confirm, bool danger = false) =>
        await ShowAsync(new DialogViewModel
        {
            Title = title,
            Message = message,
            Buttons = [new DialogButton(Loc.T("Cancel"), "cancel"), new DialogButton(confirm, "ok", primary: !danger, danger: danger)],
        }) == "ok";

    /// <summary>The standard failure dialog: reason, Retry, Diagnostics, Cancel. Never a crash.</summary>
    public Task<string?> ErrorAsync(string title, string reason, string? diagnostics, bool canRetry) =>
        ShowAsync(new DialogViewModel
        {
            Title = title,
            Message = reason,
            Details = diagnostics,
            DetailsLabel = Loc.T("Diagnostics"),
            IsError = true,
            Buttons = canRetry
                ? [new DialogButton(Loc.T("Cancel"), "cancel"), new DialogButton(Loc.T("Retry"), "retry", primary: true)]
                : [new DialogButton(Loc.T("Close"), "cancel", primary: true)],
        });

    public void CancelCurrent() => Current?.Cancel();
}

/// <summary>File pickers through the window's storage provider.</summary>
public sealed class FileDialogService
{
    private static TopLevel? Top => (Avalonia.Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow;

    public async Task<string?> PickSampleAsync()
    {
        if (Top?.StorageProvider is not { CanOpen: true } sp) return null;
        var files = await sp.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = Loc.T("SelectFile"),
            AllowMultiple = false,
            FileTypeFilter =
            [
                new FilePickerFileType(Loc.T("SupportedFiles")) { Patterns = ["*.exe", "*.dll", "*.msi", "*.ps1", "*.bat", "*.cmd", "*.vbs", "*.js", "*.lnk", "*.zip", "*.7z", "*.rar", "*.tar", "*.gz"] },
                new FilePickerFileType(Loc.T("AllFiles")) { Patterns = ["*"] },
            ],
        });
        return files.Count > 0 ? files[0].TryGetLocalPath() : null;
    }

    public async Task<string?> PickSaveAsync(string suggestedName, string extension, string? folder)
    {
        if (Top?.StorageProvider is not { CanSave: true } sp) return null;
        IStorageFolder? start = folder is null ? null : await sp.TryGetFolderFromPathAsync(folder);
        var file = await sp.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = Loc.T("Export"),
            SuggestedFileName = suggestedName,
            DefaultExtension = extension.TrimStart('.'),
            SuggestedStartLocation = start,
            ShowOverwritePrompt = true,
        });
        return file?.TryGetLocalPath();
    }
}
