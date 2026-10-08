using System.Collections.ObjectModel;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Analysis;
using Blazma.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Blazma.App.ViewModels;

public sealed record StatusItem(string Title, string Detail, Core.Events.Severity Level, string State)
{
    public bool IsOk => Level == Core.Events.Severity.Low;
    public bool IsWarn => Level == Core.Events.Severity.Medium;
    public bool IsBad => Level >= Core.Events.Severity.High;
    public bool IsInfo => Level == Core.Events.Severity.Informational;
}

/// <summary>Security Center: is the analysis environment itself ready and isolated?</summary>
public sealed partial class SecurityCenterViewModel(MainViewModel main, AnalysisCoordinator coordinator, SettingsService settings, BlazmaPaths paths) : PageViewModel
{
    public override string NavKey => "Sandbox";

    public ObservableCollection<StatusItem> Items { get; } = [];
    public ObservableCollection<CheckRow> ProviderChecks { get; } = [];
    public ObservableCollection<string> IsolationLines { get; } = [];

    [ObservableProperty] private bool _isChecking;
    [ObservableProperty] private bool _ready;

    public override async Task OnShownAsync()
    {
        IsChecking = true;
        try
        {
            var provider = coordinator.Provider(Sandbox.Providers.WindowsSandbox.WindowsSandboxProvider.ProviderId);
            var availability = await provider.CheckAvailabilityAsync(CancellationToken.None);
            ProviderChecks.Clear();
            foreach (var c in availability.Checks) ProviderChecks.Add(new CheckRow(c.Label.Get(Loc.Instance.Code), c.Detail.Get(Loc.Instance.Code), c.Passed));
            Ready = availability.IsReady;

            var agent = availability.Checks.FirstOrDefault(c => c.Id == "agent")?.Passed ?? false;
            var storageOk = CanWrite(paths.Root);
            var dbSize = File.Exists(paths.Database) ? new FileInfo(paths.Database).Length : 0;
            var net = settings.Current;

            Items.Clear();
            Items.Add(new(Loc.T("SandboxIsolation"), availability.IsReady ? Loc.T("IsolationReady") : Loc.T("IsolationNotReady"),
                availability.IsReady ? Core.Events.Severity.Low : Core.Events.Severity.Medium, availability.IsReady ? Loc.T("StateReady") : Loc.T("StateNeedsSetup")));
            Items.Add(new(Loc.T("AgentConnection"), agent ? Loc.T("AgentPresent") : Loc.T("AgentMissing"),
                agent ? Core.Events.Severity.Low : Core.Events.Severity.Medium, agent ? Loc.T("StateReady") : Loc.T("StateMissing")));
            Items.Add(new(Loc.T("NetworkPolicyTitle"), Loc.T("NetworkPolicyDetail"), Core.Events.Severity.Low, Loc.T("StateDisabledDefault")));
            Items.Add(new(Loc.T("HostProtection"), Loc.T("HostProtectionDetail"), Core.Events.Severity.Low, Loc.T("StateActive")));
            Items.Add(new(Loc.T("Storage"), Loc.F("StorageDetail", paths.Root, Fmt.Size(dbSize)), storageOk ? Core.Events.Severity.Low : Core.Events.Severity.High, storageOk ? Loc.T("StateWritable") : Loc.T("StateReadOnly")));
            Items.Add(new(Loc.T("AppIntegrity"), Loc.F("IntegrityDetail", typeof(SecurityCenterViewModel).Assembly.GetName().Version?.ToString(3) ?? "?"), Core.Events.Severity.Informational, Loc.T("StateDevBuild")));
            Items.Add(new(Loc.T("Privacy"), Loc.T("PrivacyDetail"), Core.Events.Severity.Low, Loc.T("StateLocalOnly")));

            IsolationLines.Clear();
            foreach (var key in new[] { "IsoNetwork", "IsoGpu", "IsoClipboard", "IsoPrinter", "IsoAudio", "IsoProtected", "IsoFolders", "IsoChannel", "IsoDisposable" })
                IsolationLines.Add(Loc.T(key));
        }
        finally { IsChecking = false; }
    }

    private static bool CanWrite(string dir)
    {
        try
        {
            Directory.CreateDirectory(dir);
            var probe = Path.Combine(dir, ".write-test");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    [RelayCommand] private Task Recheck() => OnShownAsync();
    [RelayCommand] private void OpenDataFolder() => main.OpenFolder(paths.Root);
    protected override void OnLanguageChanged() => _ = OnShownAsync();
}
