using System.ComponentModel;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Settings;
using Blazma.Core.Text;
using Blazma.Sandbox.Processes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using static Blazma.Sandbox.Providers.VirtualMachine.VirtualMachineChecks;

namespace Blazma.Sandbox.Providers.VirtualMachine.VirtualBox;

public sealed record VirtualBoxOptions : VirtualMachineOptions
{
    /// <summary>Full path to VBoxManage; null or empty uses <see cref="DefaultVBoxManagePath"/>.</summary>
    public string? VBoxManagePath { get; init; }

    public string VmName { get; init; } = string.Empty;
    public string Snapshot { get; init; } = "clean";

    /// <summary>A window the analyst can watch, or headless. Interactive analyses always get a window.</summary>
    public VmDisplay Display { get; init; } = VmDisplay.Window;

    /// <summary>Windows PowerShell inside the guest, used to list the output folder and to probe the guest.</summary>
    public string GuestPowerShell { get; init; } = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

    public string ResolvedVBoxManagePath => string.IsNullOrWhiteSpace(VBoxManagePath) ? DefaultVBoxManagePath : VBoxManagePath;

    /// <summary>Where the VirtualBox installer puts VBoxManage (it also records the folder in VBOX_MSI_INSTALL_PATH).</summary>
    public static string DefaultVBoxManagePath
    {
        get
        {
            if (!OperatingSystem.IsWindows()) return "/usr/bin/VBoxManage";
            var installed = Environment.GetEnvironmentVariable("VBOX_MSI_INSTALL_PATH");
            return Path.Combine(string.IsNullOrWhiteSpace(installed) ? @"C:\Program Files\Oracle\VirtualBox" : installed, "VBoxManage.exe");
        }
    }

    /// <summary>Builds the options from the user's settings.</summary>
    public static VirtualBoxOptions FromSettings(VirtualMachineSettings vm, AdvancedSettings? advanced, string workRoot, string agentFolder, bool stopWhenTreeExits = true) =>
        Apply(new VirtualBoxOptions
        {
            WorkRoot = workRoot,
            AgentFolder = agentFolder,
            VBoxManagePath = vm.VBoxManagePath,
            VmName = vm.VirtualBoxVm,
            Snapshot = vm.VirtualBoxSnapshot,
            Display = vm.VirtualBoxDisplay,
        }, vm, advanced, stopWhenTreeExits);
}

/// <summary>
/// Runs samples in a user-prepared VirtualBox VM, restored from a clean snapshot before and after
/// every analysis. Works on Windows Home. A full VM is harder for a sample to recognise than
/// Windows Sandbox, but it is only as isolated as the user configured it: the provider refuses a VM
/// with a connected network adapter unless the analysis enables the network.
/// </summary>
public sealed class VirtualBoxProvider(VirtualBoxOptions options, ISecretProtector secrets, IProcessRunner? runner = null, ILoggerFactory? loggers = null) : ISandboxProvider
{
    public const string ProviderId = "virtualbox";

    private readonly IProcessRunner _runner = runner ?? ProcessRunner.Instance;

    public string Id => ProviderId;
    public LocalizedText DisplayName { get; } = new("VirtualBox virtual machine", "جهاز افتراضي في VirtualBox");
    public bool IsDemo => false;

    public Task<ProviderAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken) =>
        CheckAvailabilityAsync(NetworkPolicy.Disabled, cancellationToken);

    /// <summary>Checks with the analysis' network policy (a connected adapter is accepted when the network is enabled).</summary>
    public async Task<ProviderAvailability> CheckAvailabilityAsync(NetworkPolicy network, CancellationToken cancellationToken)
    {
        var checks = new List<ProviderCheck>();
        var vbox = new VBoxManage(_runner, options.ResolvedVBoxManagePath, TimeSpan.FromSeconds(30));

        var toolOk = File.Exists(vbox.Executable);
        checks.Add(Check("vboxmanage", new("VirtualBox", "VirtualBox"), toolOk,
            toolOk ? new("VBoxManage was found.", "عُثر على VBoxManage.")
                   : new("Install VirtualBox, or set the path to VBoxManage.exe in Settings.", "ثبّت VirtualBox، أو حدّد مسار VBoxManage.exe في الإعدادات.")));

        string? vmId = null;
        if (!toolOk) checks.Add(Check("vm", VmLabel, false, NotChecked));
        else if (string.IsNullOrWhiteSpace(options.VmName)) checks.Add(Check("vm", VmLabel, false, VmNotSet));
        else
        {
            var list = await TryRunAsync(vbox, ["list", "vms"], cancellationToken).ConfigureAwait(false);
            var matches = list is { Succeeded: true } ? VBoxManage.ParseVmList(list.StandardOutput).Where(v => v.Name == options.VmName).ToList() : [];
            if (list is not { Succeeded: true })
                checks.Add(Check("vm", VmLabel, false, new("VBoxManage could not list the virtual machines. Open VirtualBox once to finish its setup.", "تعذّر على VBoxManage عرض الأجهزة الافتراضية. افتح VirtualBox مرة واحدة لإكمال إعداده.")));
            else if (matches.Count == 0) checks.Add(Check("vm", VmLabel, false, VmMissing));
            else if (matches.Count > 1) checks.Add(Check("vm", VmLabel, false, VmAmbiguous));
            else { vmId = matches[0].Id; checks.Add(Check("vm", VmLabel, true, Found)); }
        }

        var snapshotLabel = new LocalizedText("Clean snapshot", "اللقطة النظيفة");
        if (vmId is null) checks.Add(Check("snapshot", snapshotLabel, false, NotChecked));
        else
        {
            var snapshots = await TryRunAsync(vbox, ["snapshot", vmId, "list", "--machinereadable"], cancellationToken).ConfigureAwait(false);
            var found = snapshots is { Succeeded: true } ? VBoxManage.FindSnapshots(VBoxManage.ParseMachineReadable(snapshots.StandardOutput), options.Snapshot).Count : 0;
            checks.Add(Check("snapshot", snapshotLabel, found == 1,
                found == 1 ? new("Found; it is restored before and after every analysis.", "موجودة، وتُستعاد قبل كل تحليل وبعده.")
                : found > 1 ? new($"Several snapshots are named \"{options.Snapshot}\". Rename the others.", $"توجد عدة لقطات باسم \"{options.Snapshot}\". غيّر أسماء الأخرى.")
                : new($"The virtual machine has no snapshot named \"{options.Snapshot}\". Take one of the prepared, clean state (see docs/VIRTUAL-MACHINES.md).",
                      $"لا توجد لقطة باسم \"{options.Snapshot}\" لهذا الجهاز الافتراضي. التقط لقطة للحالة النظيفة المُعدّة (راجع docs/VIRTUAL-MACHINES.md).")));
        }

        IReadOnlyList<string>? connected = null;
        var running = false;
        if (vmId is not null)
        {
            var info = await TryRunAsync(vbox, ["showvminfo", vmId, "--machinereadable"], cancellationToken).ConfigureAwait(false);
            if (info is { Succeeded: true })
            {
                var values = VBoxManage.ParseMachineReadable(info.StandardOutput);
                connected = VBoxManage.ConnectedAdapters(values);
                running = VBoxManage.IsRunning(values);
            }
        }
        checks.Add(VirtualMachineChecks.Network(options, network, connected,
            new("Set every adapter to \"Not attached\" (or disable it) and take the snapshot again, or enable network access for this analysis.",
                "اضبط كل محوّل على \"غير متصل\" (أو عطّله) ثم التقط اللقطة من جديد، أو فعّل الوصول إلى الشبكة لهذا التحليل.")));
        checks.Add(Check("instance", InstanceLabel, vmId is not null && connected is not null && !running,
            vmId is null || connected is null ? NotChecked : running ? VirtualMachineChecks.Running : Ready));

        checks.Add(Credentials(options, secrets));
        checks.Add(GuestFolder(options));
        checks.Add(Agent(options));
        return new ProviderAvailability(Readiness(checks, supported: true, running), checks);
    }

    public Task<ISandboxSession> CreateSessionAsync(SandboxSessionRequest request, CancellationToken cancellationToken)
    {
        var password = RequirePassword(options, secrets);
        ISandboxSession session = new VirtualBoxSession(request, options, _runner, password, loggers?.CreateLogger<VirtualBoxSession>() ?? NullLogger<VirtualBoxSession>.Instance);
        return Task.FromResult(session);
    }

    private static async Task<ProcessResult?> TryRunAsync(VBoxManage vbox, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        try { return await vbox.RunAsync(arguments, cancellationToken).ConfigureAwait(false); }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException) { return null; }
    }
}
