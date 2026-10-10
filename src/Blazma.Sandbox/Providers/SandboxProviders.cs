using Blazma.Core.Abstractions;
using Blazma.Core.Settings;
using Blazma.Sandbox.Channel;
using Blazma.Sandbox.Providers.Demo;
using Blazma.Sandbox.Providers.VirtualMachine.HyperV;
using Blazma.Sandbox.Providers.VirtualMachine.VirtualBox;
using Blazma.Sandbox.Providers.WindowsSandbox;
using Microsoft.Extensions.Logging;

namespace Blazma.Sandbox.Providers;

/// <summary>
/// Builds the analysis environment named by a provider id from the user's settings. Shared by
/// the desktop app and the command line so both run samples the same way.
/// </summary>
public static class SandboxProviders
{
    /// <summary>Every provider id, in the order shown to the user.</summary>
    public static IReadOnlyList<string> Ids { get; } =
        [WindowsSandboxProvider.ProviderId, VirtualBoxProvider.ProviderId, HyperVProvider.ProviderId, DemoSandboxProvider.ProviderId];

    /// <summary>The agent files are expected in an "agent" folder next to the executable.</summary>
    public static string DefaultAgentFolder => Path.Combine(AppContext.BaseDirectory, "agent");

    public static ISandboxProvider Create(
        string? id,
        BlazmaSettings settings,
        string workRoot,
        string agentFolder,
        ISecretProtector secrets,
        ILoggerFactory? loggers = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var analysis = settings.Analysis;
        var advanced = settings.Advanced;
        return (id ?? analysis.ProviderId) switch
        {
            DemoSandboxProvider.ProviderId => new DemoSandboxProvider(TimeProvider.System, advanced.DemoSpeed),
            VirtualBoxProvider.ProviderId => new VirtualBoxProvider(
                VirtualBoxOptions.FromSettings(settings.VirtualMachines, advanced, workRoot, agentFolder, analysis.StopWhenTreeExits), secrets, loggers: loggers),
            HyperVProvider.ProviderId => new HyperVProvider(
                HyperVOptions.FromSettings(settings.VirtualMachines, advanced, workRoot, agentFolder, analysis.StopWhenTreeExits), secrets, loggers: loggers),
            _ => new WindowsSandboxProvider(new WindowsSandboxOptions
            {
                WorkRoot = workRoot,
                AgentFolder = agentFolder,
                AgentLimits = new AgentLimits(
                    analysis.MaxDroppedFiles,
                    analysis.MaxDroppedFileMb * 1024L * 1024,
                    analysis.MaxMemoryDumpMb * 1024L * 1024,
                    AgentLimits.Default.MaxScreenshots),
                MemoryMb = advanced.SandboxMemoryMb,
                OutboxQuotaBytes = advanced.OutboxQuotaBytes,
                // At least 30 s: shorter limits report healthy runs as interrupted while a sample keeps the sandbox busy.
                HeartbeatTimeout = TimeSpan.FromSeconds(Math.Max(30, advanced.AgentHeartbeatTimeoutSeconds)),
                StopWhenTreeExits = analysis.StopWhenTreeExits,
            }, loggers),
        };
    }
}
