using System.ComponentModel;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Settings;
using Blazma.Core.Text;
using Blazma.Sandbox.Processes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using static Blazma.Sandbox.Providers.VirtualMachine.VirtualMachineChecks;

namespace Blazma.Sandbox.Providers.VirtualMachine.HyperV;

public sealed record HyperVOptions : VirtualMachineOptions
{
    public string VmName { get; init; } = string.Empty;
    public string Checkpoint { get; init; } = "clean";

    /// <summary>Windows PowerShell 5.1, which ships the Hyper-V module.</summary>
    public string PowerShellPath { get; init; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");

    /// <summary>Name of the scheduled task that starts the agent inside the guest (removed by the checkpoint restore).</summary>
    public string AgentTaskName { get; init; } = "BlazmaAgent";

    /// <summary>Builds the options from the user's settings.</summary>
    public static HyperVOptions FromSettings(VirtualMachineSettings vm, AdvancedSettings? advanced, string workRoot, string agentFolder, bool stopWhenTreeExits = true) =>
        Apply(new HyperVOptions
        {
            WorkRoot = workRoot,
            AgentFolder = agentFolder,
            VmName = vm.HyperVVm,
            Checkpoint = vm.HyperVCheckpoint,
        }, vm, advanced, stopWhenTreeExits);
}

/// <summary>
/// Runs samples in a user-prepared Hyper-V VM, restored from a clean checkpoint before and after
/// every analysis. Uses PowerShell Direct, so the host and the guest need no network between them.
/// Blazma itself is not elevated: the user must be in the local "Hyper-V Administrators" group.
/// </summary>
public sealed class HyperVProvider : ISandboxProvider
{
    public const string ProviderId = "hyperv";

    private readonly HyperVOptions _options;
    private readonly ISecretProtector _secrets;
    private readonly IProcessRunner _runner;
    private readonly ILoggerFactory? _loggers;
    private readonly bool _isWindows;

    public HyperVProvider(HyperVOptions options, ISecretProtector secrets, IProcessRunner? runner = null, ILoggerFactory? loggers = null)
        : this(options, secrets, runner, loggers, OperatingSystem.IsWindows())
    {
    }

    /// <summary>For tests on non-Windows machines.</summary>
    internal HyperVProvider(HyperVOptions options, ISecretProtector secrets, IProcessRunner? runner, ILoggerFactory? loggers, bool isWindows)
    {
        _options = options;
        _secrets = secrets;
        _runner = runner ?? ProcessRunner.Instance;
        _loggers = loggers;
        _isWindows = isWindows;
    }

    public string Id => ProviderId;
    public LocalizedText DisplayName { get; } = new("Hyper-V virtual machine", "جهاز افتراضي في Hyper-V");
    public bool IsDemo => false;

    public Task<ProviderAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken) =>
        CheckAvailabilityAsync(NetworkPolicy.Disabled, cancellationToken);

    /// <summary>Checks with the analysis' network policy (a connected adapter is accepted when the network is enabled).</summary>
    public async Task<ProviderAvailability> CheckAvailabilityAsync(NetworkPolicy network, CancellationToken cancellationToken)
    {
        var checks = new List<ProviderCheck>();
        var osLabel = new LocalizedText("Windows with Hyper-V", "نظام Windows مع Hyper-V");
        if (!_isWindows)
        {
            checks.Add(Check("os", osLabel, false, new("Hyper-V needs Windows 10 or 11 Pro, Enterprise or Education.", "يتطلب Hyper-V نظام Windows 10 أو 11 بإصدار Pro أو Enterprise أو Education.")));
            return new ProviderAvailability(ProviderReadiness.NotSupported, checks);
        }
        checks.Add(Check("os", osLabel, true, new("Windows.", "نظام Windows.")));

        PowerShellOutput? output;
        try
        {
            output = await new PowerShellHost(_runner, _options.PowerShellPath, TimeSpan.FromSeconds(60))
                .RunAsync(HyperVScripts.Availability(_options.VmName, _options.Checkpoint), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException) { output = null; }

        var moduleOk = output is { Ok: true } && output.Get("module") == "True";
        checks.Add(Check("module", new("Hyper-V PowerShell module", "وحدة Hyper-V في PowerShell"), moduleOk,
            moduleOk ? new("Installed.", "مثبّتة.")
            : new("Turn on \"Hyper-V\" (including the Hyper-V Module for Windows PowerShell) in Windows Features, then restart.",
                  "فعّل \"Hyper-V\" (بما في ذلك وحدة Hyper-V لـWindows PowerShell) من ميزات Windows، ثم أعد التشغيل.")));

        var accessOk = moduleOk && output!.Get("access") == "True";
        checks.Add(Check("access", new("Permission to manage virtual machines", "صلاحية إدارة الأجهزة الافتراضية"), accessOk,
            !moduleOk ? NotChecked
            : accessOk ? new("Granted.", "متاحة.")
            : new("Add your account to the local \"Hyper-V Administrators\" group, then sign out and in again. Blazma does not run as administrator.",
                  "أضف حسابك إلى مجموعة \"Hyper-V Administrators\" المحلية، ثم سجّل الخروج وأعد تسجيل الدخول. لا يعمل Blazma بصلاحيات المسؤول.")));

        var vmCount = int.TryParse(output?.Get("vms"), out var count) ? count : -1;
        var vmOk = accessOk && vmCount == 1;
        checks.Add(Check("vm", VmLabel, vmOk,
            string.IsNullOrWhiteSpace(_options.VmName) ? VmNotSet
            : !accessOk ? NotChecked
            : vmCount == 0 ? VmMissing
            : vmCount > 1 ? VmAmbiguous
            : vmOk ? Found : NotChecked));

        var checkpoints = vmOk && int.TryParse(output?.Get("checkpoints"), out var cps) ? cps : -1;
        checks.Add(Check("checkpoint", new("Clean checkpoint", "نقطة التحقق النظيفة"), checkpoints == 1,
            !vmOk ? NotChecked
            : checkpoints == 1 ? new("Found; it is restored before and after every analysis.", "موجودة، وتُستعاد قبل كل تحليل وبعده.")
            : checkpoints > 1 ? new($"Several checkpoints are named \"{_options.Checkpoint}\". Rename the others.", $"توجد عدة نقاط تحقق باسم \"{_options.Checkpoint}\". غيّر أسماء الأخرى.")
            : new($"The virtual machine has no checkpoint named \"{_options.Checkpoint}\". Create one of the prepared, clean state (see docs/VIRTUAL-MACHINES.md).",
                  $"لا توجد نقطة تحقق باسم \"{_options.Checkpoint}\" لهذا الجهاز الافتراضي. أنشئ نقطة تحقق للحالة النظيفة المُعدّة (راجع docs/VIRTUAL-MACHINES.md).")));

        var state = output?.Get("state");
        var running = vmOk && state is not null && state is not ("Off" or "Saved");
        checks.Add(VirtualMachineChecks.Network(_options, network, vmOk ? output!.All("adapter").ToList() : null,
            new("Set every network adapter to \"Not connected\" and create the checkpoint again, or enable network access for this analysis.",
                "اضبط كل محوّل شبكة على \"غير متصل\" ثم أنشئ نقطة التحقق من جديد، أو فعّل الوصول إلى الشبكة لهذا التحليل.")));
        checks.Add(Check("instance", InstanceLabel, vmOk && !running, !vmOk ? NotChecked : running ? VirtualMachineChecks.Running : Ready));

        checks.Add(Credentials(_options, _secrets));
        checks.Add(GuestFolder(_options));
        checks.Add(Agent(_options));
        return new ProviderAvailability(Readiness(checks, supported: true, running), checks);
    }

    public Task<ISandboxSession> CreateSessionAsync(SandboxSessionRequest request, CancellationToken cancellationToken)
    {
        var password = RequirePassword(_options, _secrets);
        ISandboxSession session = new HyperVSession(request, _options, _runner, password, _loggers?.CreateLogger<HyperVSession>() ?? NullLogger<HyperVSession>.Instance);
        return Task.FromResult(session);
    }
}
