using Blazma.Core.Abstractions;
using Blazma.Core.Settings;
using Blazma.Sandbox.Channel;
using Blazma.Sandbox.Processes;
using Microsoft.Extensions.Logging;

namespace Blazma.Sandbox.Providers.VirtualMachine.VirtualBox;

/// <summary>
/// One analysis in a VirtualBox VM, driven entirely through VBoxManage:
/// <c>snapshot restore</c>, <c>startvm</c>, <c>guestproperty get</c>, and <c>guestcontrol</c>
/// (<c>run</c>, <c>mkdir</c>, <c>copyto</c>, <c>rm</c>, <c>start</c>, <c>copyfrom</c>) with the
/// guest password in a short-lived <c>--passwordfile</c>, never on the command line.
/// </summary>
internal sealed class VirtualBoxSession(SandboxSessionRequest request, VirtualBoxOptions options, IProcessRunner runner, string guestPassword, ILogger logger)
    : VirtualMachineSession(request, options, guestPassword, logger), IInteractiveSession
{
    private const int MaxFilesPerCopy = 32;
    private const int MaxArgumentChars = 16_000;
    private readonly VBoxManage _vbox = new(runner, options.ResolvedVBoxManagePath, options.CommandTimeout);
    private string? _vmId;
    private string? _snapshotId;

    internal string? VmId => _vmId;
    internal string? SnapshotId => _snapshotId;

    protected override async Task InspectMachineAsync(CancellationToken cancellationToken)
    {
        var list = await _vbox.RequireAsync(["list", "vms"], "list the virtual machines", cancellationToken).ConfigureAwait(false);
        var matches = VBoxManage.ParseVmList(list.StandardOutput).Where(v => v.Name == options.VmName).ToList();
        if (matches.Count != 1)
            throw new InvalidOperationException(matches.Count == 0 ? "The configured VirtualBox virtual machine was not found." : "Several VirtualBox virtual machines have the configured name.");
        var vmId = matches[0].Id;

        var snapshots = await _vbox.RequireAsync(["snapshot", vmId, "list", "--machinereadable"], "list the snapshots", cancellationToken).ConfigureAwait(false);
        var found = VBoxManage.FindSnapshots(VBoxManage.ParseMachineReadable(snapshots.StandardOutput), options.Snapshot);
        if (found.Count != 1)
            throw new InvalidOperationException(found.Count == 0 ? "The virtual machine has no snapshot with the configured name." : "Several snapshots have the configured name.");

        var info = await _vbox.RequireAsync(["showvminfo", vmId, "--machinereadable"], "read the virtual machine settings", cancellationToken).ConfigureAwait(false);
        if (VBoxManage.IsRunning(VBoxManage.ParseMachineReadable(info.StandardOutput)))
            throw new InvalidOperationException("The virtual machine is already running. Close it first; Blazma restores the snapshot and starts it itself.");

        _vmId = vmId;
        _snapshotId = found[0];
    }

    protected override Task RestoreSnapshotAsync(CancellationToken cancellationToken) =>
        _vbox.RequireAsync(["snapshot", _vmId!, "restore", _snapshotId!], "restore the clean snapshot", cancellationToken);

    protected override async Task<IReadOnlyList<string>> GetConnectedAdaptersAsync(CancellationToken cancellationToken)
    {
        var info = await _vbox.RequireAsync(["showvminfo", _vmId!, "--machinereadable"], "read the virtual machine settings", cancellationToken).ConfigureAwait(false);
        return VBoxManage.ConnectedAdapters(VBoxManage.ParseMachineReadable(info.StandardOutput));
    }

    protected override Task StartMachineAsync(CancellationToken cancellationToken)
    {
        var type = options.Display == VmDisplay.Window || Request.Options.Interactive ? "gui" : "headless";
        return _vbox.RequireAsync(["startvm", _vmId!, "--type", type], "start the virtual machine", cancellationToken);
    }

    protected override async Task WaitForGuestAsync(CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + options.BootTimeout;
        var last = "the Guest Additions did not report a version";
        while (true)
        {
            var property = await _vbox.RunAsync(["guestproperty", "get", _vmId!, VBoxManage.GuestAdditionsVersionProperty], cancellationToken).ConfigureAwait(false);
            if (property.Succeeded && property.StandardOutput.TrimStart().StartsWith("Value:", StringComparison.Ordinal))
            {
                var probe = await GuestControlAsync("run",
                    ["--exe=" + options.GuestPowerShell, "--timeout=60000", "--wait-stdout", "--", options.GuestPowerShell, "-NoProfile", "-NonInteractive", "-Command", "exit 0"],
                    cancellationToken).ConfigureAwait(false);
                if (probe.Succeeded) return;
                if (IsLogonFailure(probe))
                    throw new InvalidOperationException("The virtual machine rejected the guest user name or password. Check the guest account in Settings.");
                last = probe.Describe();
            }
            if (DateTimeOffset.UtcNow > deadline)
                throw new TimeoutException($"The virtual machine did not become ready in time ({last}). Check that the Guest Additions are installed in the snapshot.");
            await Task.Delay(options.PollInterval, cancellationToken).ConfigureAwait(false);
        }
    }

    protected override async Task CreateGuestFoldersAsync(IReadOnlyList<string> guestFolders, CancellationToken cancellationToken) =>
        Require(await GuestControlAsync("mkdir", ["--parents", .. guestFolders], cancellationToken).ConfigureAwait(false), "create the working folders in the guest");

    protected override async Task CopyToGuestAsync(IReadOnlyList<string> hostFiles, string guestFolder, CancellationToken cancellationToken)
    {
        foreach (var batch in Batches(hostFiles))
            Require(await GuestControlAsync("copyto", ["--target-directory=" + guestFolder, .. batch], cancellationToken).ConfigureAwait(false), "copy files into the guest");
    }

    /// <summary>Removes the old copy first so the file is replaced on every VirtualBox version.</summary>
    protected override async Task ReplaceGuestFileAsync(string hostFile, string guestFolder, CancellationToken cancellationToken)
    {
        await GuestControlAsync("rm", ["--force", GuestPaths.Join(guestFolder, Path.GetFileName(hostFile))], cancellationToken).ConfigureAwait(false);
        await CopyToGuestAsync([hostFile], guestFolder, cancellationToken).ConfigureAwait(false);
    }

    /// <summary><c>guestcontrol start</c> returns once the process runs and leaves it running in the guest.</summary>
    protected override async Task StartAgentAsync(CancellationToken cancellationToken) =>
        Require(await GuestControlAsync("start",
            ["--exe=" + Guest.AgentExecutable, "--", Guest.AgentExecutable, Guest.In, Guest.Out],
            cancellationToken).ConfigureAwait(false), "start the monitoring agent in the guest");

    protected override async Task<bool> FetchOutboxAsync(GuestOutboxSync sync, string incomingFolder, CancellationToken cancellationToken)
    {
        var listing = await GuestControlAsync("run",
            ["--exe=" + options.GuestPowerShell, "--timeout=60000", "--wait-stdout", "--", options.GuestPowerShell, "-NoProfile", "-NonInteractive", "-EncodedCommand", PowerShellText.EncodeCommand(ListingScript(Guest.Out))],
            cancellationToken).ConfigureAwait(false);
        if (!listing.Succeeded) return false;

        var selected = sync.Select(VBoxManage.ParseListing(listing.StandardOutput));
        if (selected.Count == 0) return true;
        var copy = await GuestControlAsync("copyfrom",
            ["--target-directory=" + incomingFolder, .. selected.Select(f => GuestPaths.Join(Guest.Out, f.Name))],
            cancellationToken).ConfigureAwait(false);
        return copy.Succeeded;
    }

    /// <summary>Lists complete, non-link files as <c>length|name</c>. The folder is a validated path; the script holds no secret.</summary>
    internal static string ListingScript(string guestOut) =>
        "$ErrorActionPreference = 'Stop'; "
        + $"Get-ChildItem -LiteralPath {PowerShellText.Quote(guestOut)} -File -Force | "
        + "Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | "
        + "ForEach-Object { '{0}|{1}' -f $_.Length, $_.Name }";

    protected override async Task ResetMachineAsync(CancellationToken cancellationToken)
    {
        if (_vmId is null || _snapshotId is null) return;
        await _vbox.RunAsync(["controlvm", _vmId, "poweroff"], cancellationToken).ConfigureAwait(false);

        // The session lock is released a moment after power-off; wait for a stopped state, then restore.
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(60);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var info = await _vbox.RunAsync(["showvminfo", _vmId, "--machinereadable"], cancellationToken).ConfigureAwait(false);
            if (info.Succeeded && !VBoxManage.IsRunning(VBoxManage.ParseMachineReadable(info.StandardOutput))) break;
            await Task.Delay(options.PollInterval, cancellationToken).ConfigureAwait(false);
        }

        ProcessResult? restore = null;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            restore = await _vbox.RunAsync(["snapshot", _vmId, "restore", _snapshotId], cancellationToken).ConfigureAwait(false);
            if (restore.Succeeded) return;
            await Task.Delay(options.PollInterval, cancellationToken).ConfigureAwait(false);
        }
        throw new InvalidOperationException($"VirtualBox could not restore the clean snapshot ({restore?.Describe()}).");
    }

    /// <summary><c>VBoxManage guestcontrol &lt;uuid&gt; &lt;command&gt; --username=… --passwordfile=… …</c>, with a fresh password file per call.</summary>
    private async Task<ProcessResult> GuestControlAsync(string command, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        using var secret = SecretFile.Create(SecretsFolder, GuestPassword);
        return await _vbox.RunAsync(
            ["guestcontrol", _vmId!, command, "--username=" + options.GuestUser, "--passwordfile=" + secret.Path, .. arguments],
            cancellationToken).ConfigureAwait(false);
    }

    private static void Require(ProcessResult result, string what)
    {
        if (!result.Succeeded) throw new InvalidOperationException($"VirtualBox could not {what} ({result.Describe()}).");
    }

    private static bool IsLogonFailure(ProcessResult result) =>
        result.StandardError.Contains("VERR_AUTHENTICATION_FAILURE", StringComparison.Ordinal)
        || result.StandardError.Contains("not able to logon", StringComparison.OrdinalIgnoreCase);

    private static IEnumerable<IReadOnlyList<string>> Batches(IReadOnlyList<string> files)
    {
        var batch = new List<string>();
        var chars = 0;
        foreach (var file in files)
        {
            if (batch.Count > 0 && (batch.Count >= MaxFilesPerCopy || chars + file.Length > MaxArgumentChars))
            {
                yield return batch;
                batch = [];
                chars = 0;
            }
            batch.Add(file);
            chars += file.Length + 3;
        }
        if (batch.Count > 0) yield return batch;
    }
}
