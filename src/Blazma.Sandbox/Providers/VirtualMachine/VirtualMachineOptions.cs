using System.Text;
using System.Text.RegularExpressions;
using Blazma.Core.Settings;
using Blazma.Sandbox.Channel;

namespace Blazma.Sandbox.Providers.VirtualMachine;

/// <summary>Settings shared by the providers that run the agent inside a user-prepared virtual machine.</summary>
public abstract record VirtualMachineOptions
{
    /// <summary>Host root for per-analysis staging folders (deleted afterwards).</summary>
    public required string WorkRoot { get; init; }

    /// <summary>Folder containing the published Blazma.Agent.exe (self-contained).</summary>
    public required string AgentFolder { get; init; }

    /// <summary>An administrator account inside the guest (not on the host).</summary>
    public string GuestUser { get; init; } = string.Empty;

    /// <summary>The guest password as stored in settings, protected with <see cref="Core.Abstractions.ISecretProtector"/>.</summary>
    public string? ProtectedGuestPassword { get; init; }

    /// <summary>Working folder inside the guest; each analysis uses a sub-folder named after its id.</summary>
    public string GuestWorkFolder { get; init; } = @"C:\Blazma";

    /// <summary>Refuse to run when the VM has a connected network adapter, unless the analysis enables the network.</summary>
    public bool RequireDisconnectedNetwork { get; init; } = true;

    public long OutboxQuotaBytes { get; init; } = 512L * 1024 * 1024;
    public TimeSpan HeartbeatTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>From starting the VM until the guest accepts commands.</summary>
    public TimeSpan BootTimeout { get; init; } = TimeSpan.FromMinutes(5);
    public TimeSpan AgentHelloTimeout { get; init; } = TimeSpan.FromMinutes(3);

    /// <summary>Upper bound for one VBoxManage or PowerShell invocation.</summary>
    public TimeSpan CommandTimeout { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>Pause between two copies of the guest output folder.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Consecutive failed copies of the guest output before the VM is considered lost.</summary>
    public int MaxSyncFailures { get; init; } = 5;

    public bool StopWhenTreeExits { get; init; } = true;
    public AgentLimits AgentLimits { get; init; } = AgentLimits.Default;

    /// <summary>Copies the settings every VM provider shares.</summary>
    protected static T Apply<T>(T options, VirtualMachineSettings vm, AdvancedSettings? advanced, bool stopWhenTreeExits) where T : VirtualMachineOptions
    {
        advanced ??= new AdvancedSettings();
        return options with
        {
            GuestUser = vm.GuestUser,
            ProtectedGuestPassword = vm.GuestPassword,
            GuestWorkFolder = vm.GuestWorkFolder,
            RequireDisconnectedNetwork = vm.RequireDisconnectedNetwork,
            OutboxQuotaBytes = advanced.OutboxQuotaBytes,
            HeartbeatTimeout = TimeSpan.FromSeconds(Math.Max(5, advanced.AgentHeartbeatTimeoutSeconds)),
            StopWhenTreeExits = stopWhenTreeExits,
        };
    }

    /// <summary>Leaves the (protected) password out of logs.</summary>
    protected virtual bool PrintMembers(StringBuilder builder)
    {
        builder.Append($"WorkRoot = {WorkRoot}, AgentFolder = {AgentFolder}, GuestUser = {GuestUser}, GuestWorkFolder = {GuestWorkFolder}, RequireDisconnectedNetwork = {RequireDisconnectedNetwork}");
        return true;
    }
}

/// <summary>Paths inside a Windows guest. Built with backslashes whatever the host OS is.</summary>
public static partial class GuestPaths
{
    /// <summary>
    /// A drive-rooted folder with at least one segment of letters, digits, spaces and <c>_ - . ( )</c>.
    /// No quotes, wildcards, variables or <c>..</c>, so the path is inert in every guest command.
    /// </summary>
    public static bool IsValidWorkFolder(string? folder)
    {
        if (string.IsNullOrWhiteSpace(folder) || folder.Length > 120) return false;
        var trimmed = folder.TrimEnd('\\');
        if (!WorkFolderRegex().IsMatch(trimmed)) return false;
        return trimmed.Split('\\').Skip(1).All(s => s.Trim('.').Length > 0 && !s.EndsWith(' ') && !s.EndsWith('.') && !s.StartsWith(' '));
    }

    public static string Join(string folder, params string[] parts) =>
        string.Join('\\', new[] { folder.TrimEnd('\\') }.Concat(parts.Select(p => p.Trim('\\'))));

    [GeneratedRegex(@"^[A-Za-z]:(\\[\p{L}\p{N} _\-.()]+)+$", RegexOptions.CultureInvariant)]
    private static partial Regex WorkFolderRegex();
}

/// <summary>The per-analysis folders inside the guest.</summary>
public sealed record GuestLayout(string Root)
{
    public static GuestLayout For(string workFolder, Guid analysisId) => new(GuestPaths.Join(workFolder, analysisId.ToString("N")));

    public string In => GuestPaths.Join(Root, "in");
    public string Out => GuestPaths.Join(Root, "out");
    public string Agent => GuestPaths.Join(In, Contracts.Protocol.AgentFolder);
    public string Sample => GuestPaths.Join(In, Contracts.Protocol.SampleFolder);
    public string AgentExecutable => GuestPaths.Join(Agent, Contracts.Protocol.AgentExecutable);
}
