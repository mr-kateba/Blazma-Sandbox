using Blazma.Analysis.Text;
using Blazma.Core.Events;
using Blazma.Core.Processes;

namespace Blazma.Analysis.Engine;

/// <summary>
/// A clean Windows install is never quiet: indexing, updates and telemetry services run
/// constantly. Events outside the sample's process tree are treated as background noise,
/// except system-level effects in sensitive locations (persistence keys, service and task
/// stores), which are kept whoever performed them because system processes often act on
/// a sample's behalf. Processes that never act for another program (Defender, Windows Update,
/// Edge's updater, the shell's hosts, telemetry, licensing, the agent itself) are dropped
/// entirely when they are outside the tree.
/// </summary>
public static class NoiseFilter
{
    public sealed record Result(IReadOnlyList<AnalysisEvent> Kept, int Suppressed);

    /// <summary>
    /// Windows Sandbox background programs. Deliberately absent: services.exe, svchost.exe,
    /// taskhostw.exe, WmiPrvSE.exe, dllhost.exe, msiexec.exe and explorer.exe, which do work that
    /// other programs ask for (services, tasks, WMI, COM, installs, shell launches).
    /// </summary>
    private static readonly HashSet<string> BackgroundProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Microsoft Defender and Windows Security
        "MsMpEng.exe", "MpCmdRun.exe", "NisSrv.exe", "MpDefenderCoreService.exe", "MsSense.exe", "smartscreen.exe",
        "SecurityHealthService.exe", "SecurityHealthSystray.exe", "SecurityHealthHost.exe", "SgrmBroker.exe",
        // Windows Update and servicing
        "wuauclt.exe", "usoclient.exe", "MoUsoCoreWorker.exe", "WaaSMedicAgent.exe", "SIHClient.exe", "TiWorker.exe", "TrustedInstaller.exe", "UsoCoreWorker.exe",
        // Edge and its updater, OneDrive
        "MicrosoftEdgeUpdate.exe", "msedgeupdate.exe", "MicrosoftEdgeUpdateCore.exe", "elevation_service.exe", "OneDrive.exe", "OneDriveSetup.exe", "FileCoAuth.exe",
        // Shell, search and input hosts
        "SearchHost.exe", "SearchApp.exe", "SearchIndexer.exe", "SearchProtocolHost.exe", "SearchFilterHost.exe", "StartMenuExperienceHost.exe",
        "RuntimeBroker.exe", "ShellExperienceHost.exe", "TextInputHost.exe", "ctfmon.exe", "LockApp.exe", "Widgets.exe", "WidgetService.exe",
        "PhoneExperienceHost.exe", "backgroundTaskHost.exe", "UserOOBEBroker.exe", "dasHost.exe", "fontdrvhost.exe", "dwm.exe", "audiodg.exe",
        // Telemetry, compatibility, licensing, error reporting
        "CompatTelRunner.exe", "DeviceCensus.exe", "sppsvc.exe", "SppExtComObj.Exe", "wermgr.exe", "WerFault.exe",
        // Windows Sandbox container service, console hosts outside the tree, the agent and its packet capture
        "CExecSvc.exe", "conhost.exe", "Blazma.Agent.exe", "pktmon.exe",
    };

    /// <summary>Install folders of the same background programs (their helpers have many names).</summary>
    private static readonly string[] BackgroundFolders =
    [
        @"\Microsoft\Windows Defender\", @"\Windows Defender\", @"\Microsoft\EdgeUpdate\", @"\Microsoft\Edge\Application\", @"\Microsoft\EdgeWebView\",
        @"\Windows\SoftwareDistribution\", @"\Windows\SystemApps\",
    ];

    public static Result Apply(IReadOnlyList<AnalysisEvent> events, ProcessGraph graph, bool suppressBackground, IReadOnlyCollection<string> allowlist)
    {
        var kept = new List<AnalysisEvent>(events.Count);
        var suppressed = 0;
        // Without an identified sample there is no tree to scope to; keeping everything is the safe choice.
        var canScope = suppressBackground && graph.Sample is not null;

        foreach (var e in events)
        {
            var node = graph.Resolve(e);
            var isSample = node?.IsSample == true;

            if (!isSample && allowlist.Count > 0 && MatchesAllowlist(e, allowlist))
            {
                suppressed++;
                continue;
            }

            if (canScope && node?.InAnalyzedTree != true && (!KeepEvenOutsideTree(e) || IsKnownBackground(node, e)))
            {
                suppressed++;
                continue;
            }

            kept.Add(e);
        }
        return new Result(kept, suppressed);
    }

    /// <summary>A Windows Sandbox background program or the agent: never acts for the sample, so none of its activity is evidence.</summary>
    public static bool IsKnownBackground(ProcessNode? node, AnalysisEvent e)
    {
        if (e.Category == EventCategory.System) return false;
        var name = node?.Name is { Length: > 0 } n ? n : e.ProcessName;
        if (!string.IsNullOrEmpty(name) && BackgroundProcesses.Contains(name)) return true;
        if (node?.ImagePath is { } image && BackgroundFolders.Any(f => image.Contains(f, StringComparison.OrdinalIgnoreCase))) return true;
        // The agent's launcher: cmd.exe running blazma-agent.cmd.
        return node?.CommandLine?.Contains("blazma-agent", StringComparison.OrdinalIgnoreCase) == true;
    }

    private static bool KeepEvenOutsideTree(AnalysisEvent e)
    {
        if (e.Category == EventCategory.System) return true;
        if (e.RelativeTime < TimeSpan.Zero) return false;
        if (e.Action is EventAction.ServiceInstall or EventAction.ScheduledTaskCreate) return true;
        return PersistenceCatalog.IsSensitiveLocation(e);
    }

    private static bool MatchesAllowlist(AnalysisEvent e, IReadOnlyCollection<string> allowlist)
    {
        foreach (var entry in allowlist)
        {
            if (string.IsNullOrWhiteSpace(entry)) continue;
            if (Glob.IsMatch(e.ProcessName, entry)) return true;
            if (e.Target is not null && (entry.Contains('*') ? Glob.IsMatch(e.Target, entry) : e.Target.StartsWith(entry, StringComparison.OrdinalIgnoreCase)))
                return true;
        }
        return false;
    }
}
