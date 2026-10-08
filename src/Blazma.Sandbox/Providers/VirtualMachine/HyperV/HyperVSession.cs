using Blazma.Contracts;
using Blazma.Core.Abstractions;
using Blazma.Sandbox.Channel;
using Blazma.Sandbox.Processes;
using Microsoft.Extensions.Logging;

namespace Blazma.Sandbox.Providers.VirtualMachine.HyperV;

/// <summary>
/// One analysis in a Hyper-V VM through the Hyper-V module and PowerShell Direct
/// (<c>New-PSSession -VMId</c>, <c>Copy-Item -ToSession/-FromSession</c>), which needs no network
/// between host and guest. Every script goes to PowerShell on standard input.
/// </summary>
internal sealed class HyperVSession(SandboxSessionRequest request, HyperVOptions options, IProcessRunner runner, string guestPassword, ILogger logger)
    : VirtualMachineSession(request, options, guestPassword, logger), IInteractiveSession
{
    private static readonly HashSet<string> StoppedStates = new(StringComparer.OrdinalIgnoreCase) { "Off", "Saved" };
    private readonly PowerShellHost _powershell = new(runner, options.PowerShellPath, options.CommandTimeout);
    private readonly HyperVScripts.Credentials _credentials = new(options.GuestUser, guestPassword);
    private Guid? _vmId;
    private Guid? _checkpointId;
    private IReadOnlyList<string> _connectedAfterRestore = [];

    /// <summary>How long a guest operation keeps retrying to open its PowerShell Direct session.</summary>
    private static readonly TimeSpan SessionWait = TimeSpan.FromSeconds(60);
    private TimeSpan GuestTimeout => options.CommandTimeout + SessionWait;

    protected override async Task InspectMachineAsync(CancellationToken cancellationToken)
    {
        var output = await _powershell.RequireAsync(HyperVScripts.Inspect(options.VmName, options.Checkpoint), "find the virtual machine and its checkpoint", cancellationToken).ConfigureAwait(false);
        if (!Guid.TryParse(output.Get("id"), out var vmId) || !Guid.TryParse(output.Get("checkpoint"), out var checkpointId))
            throw new InvalidOperationException("Hyper-V did not report the virtual machine and checkpoint ids.");
        if (!StoppedStates.Contains(output.Get("state") ?? string.Empty))
            throw new InvalidOperationException("The virtual machine is already running. Turn it off first; Blazma restores the checkpoint and starts it itself.");
        _vmId = vmId;
        _checkpointId = checkpointId;
    }

    protected override async Task RestoreSnapshotAsync(CancellationToken cancellationToken)
    {
        var output = await _powershell.RequireAsync(HyperVScripts.Restore(_vmId!.Value, _checkpointId!.Value), "restore the clean checkpoint", cancellationToken).ConfigureAwait(false);
        _connectedAfterRestore = output.All("adapter").ToList();
    }

    protected override Task<IReadOnlyList<string>> GetConnectedAdaptersAsync(CancellationToken cancellationToken) => Task.FromResult(_connectedAfterRestore);

    protected override Task StartMachineAsync(CancellationToken cancellationToken) =>
        _powershell.RequireAsync(HyperVScripts.Start(_vmId!.Value, options.BootTimeout), "start the virtual machine", cancellationToken, options.BootTimeout + TimeSpan.FromMinutes(1));

    protected override Task WaitForGuestAsync(CancellationToken cancellationToken) =>
        _powershell.RequireAsync(HyperVScripts.Probe(_vmId!.Value, _credentials, options.BootTimeout),
            "open a PowerShell Direct session in the guest (check the guest user name and password)", cancellationToken, options.BootTimeout + TimeSpan.FromMinutes(1));

    protected override Task CreateGuestFoldersAsync(IReadOnlyList<string> guestFolders, CancellationToken cancellationToken) =>
        _powershell.RequireAsync(HyperVScripts.CreateFolders(_vmId!.Value, _credentials, SessionWait, guestFolders), "create the working folders in the guest", cancellationToken, GuestTimeout);

    protected override Task CopyToGuestAsync(IReadOnlyList<string> hostFiles, string guestFolder, CancellationToken cancellationToken) =>
        _powershell.RequireAsync(HyperVScripts.CopyTo(_vmId!.Value, _credentials, SessionWait, hostFiles, guestFolder), "copy files into the guest", cancellationToken, GuestTimeout);

    protected override Task StartAgentAsync(CancellationToken cancellationToken) =>
        _powershell.RequireAsync(HyperVScripts.StartAgent(_vmId!.Value, _credentials, SessionWait, Guest.AgentExecutable, Guest.In, Guest.Out, TaskUser(options.GuestUser), options.AgentTaskName),
            "start the monitoring agent in the guest", cancellationToken, GuestTimeout);

    protected override async Task<bool> FetchOutboxAsync(GuestOutboxSync sync, string incomingFolder, CancellationToken cancellationToken)
    {
        var output = await _powershell.RunAsync(
            HyperVScripts.Fetch(_vmId!.Value, _credentials, TimeSpan.FromSeconds(30), Guest.Out, incomingFolder, sync.CompletedNames(), sync.RemainingBytes, Protocol.Limits.MaxFileBytes),
            cancellationToken, GuestTimeout).ConfigureAwait(false);
        if (!output.Ok) return false;

        // The guest-side filter mirrors the host rules; running the listing through the host rules
        // again records unexpected names and quota problems for the report.
        var listing = output.All("file").Select(ParseListingLine).OfType<GuestFile>();
        sync.Select(listing, int.MaxValue);
        return true;
    }

    protected override async Task ResetMachineAsync(CancellationToken cancellationToken)
    {
        if (_vmId is null || _checkpointId is null) return;
        await _powershell.RequireAsync(HyperVScripts.Reset(_vmId.Value, _checkpointId.Value), "turn off the virtual machine and restore the checkpoint", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The scheduled task principal: a local account without the <c>.\</c> prefix.</summary>
    internal static string TaskUser(string user) => user.StartsWith(@".\", StringComparison.Ordinal) ? user[2..] : user;

    private static GuestFile? ParseListingLine(string value)
    {
        var at = value.IndexOf('|');
        return at > 0 && long.TryParse(value.AsSpan(0, at), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var length)
            ? new GuestFile(value[(at + 1)..], length)
            : null;
    }
}
