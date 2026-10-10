using Blazma.Core.Abstractions;
using Blazma.Core.Text;
using Blazma.Sandbox.Channel;
using Blazma.Sandbox.Processes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blazma.Sandbox.Providers.WindowsSandbox;

public sealed record WindowsSandboxOptions
{
    /// <summary>Per-analysis working folders are created under this root and deleted afterwards.</summary>
    public required string WorkRoot { get; init; }

    /// <summary>Folder containing the published Blazma.Agent.exe (self-contained).</summary>
    public required string AgentFolder { get; init; }

    public int MemoryMb { get; init; } = 4096;
    public long OutboxQuotaBytes { get; init; } = 512L * 1024 * 1024;

    /// <summary>The agent beats every 2 s; writes to the mapped folder can stall for many seconds while a sample loads the sandbox.</summary>
    public TimeSpan HeartbeatTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// A cold start takes 1 to 3 minutes and longer on slow disks; on Windows 11 24H2 and later the first
    /// start can also wait up to 2 minutes while Windows Sandbox updates itself from the Microsoft Store.
    /// </summary>
    public TimeSpan AgentHelloTimeout { get; init; } = TimeSpan.FromMinutes(8);

    /// <summary>Without a hello by then, the launcher is started again with <c>wsb exec</c> (where wsb.exe exists).</summary>
    public TimeSpan AgentStartRetryAfter { get; init; } = TimeSpan.FromMinutes(2);

    public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>How often <c>wsb list</c> is asked whether the sandbox still runs.</summary>
    public TimeSpan SandboxCheckInterval { get; init; } = TimeSpan.FromSeconds(10);
    public bool StopWhenTreeExits { get; init; } = true;
    public AgentLimits AgentLimits { get; init; } = AgentLimits.Default;
}

/// <summary>
/// Runs samples in Windows Sandbox: a disposable, hardware-virtualised Windows instance
/// that is wiped when it closes. Requires Windows 10/11 Pro, Enterprise or Education with
/// the "Windows Sandbox" feature enabled and virtualisation turned on in firmware.
/// </summary>
public sealed class WindowsSandboxProvider : ISandboxProvider
{
    public const string ProviderId = "windows-sandbox";

    private readonly WindowsSandboxOptions _options;
    private readonly ILoggerFactory? _loggers;
    private readonly IProcessRunner _runner;
    private readonly IWindowsSandboxHost _host;

    public WindowsSandboxProvider(WindowsSandboxOptions options, ILoggerFactory? loggers = null)
        : this(options, loggers, ProcessRunner.Instance, WindowsSandboxHost.Instance) { }

    internal WindowsSandboxProvider(WindowsSandboxOptions options, ILoggerFactory? loggers, IProcessRunner runner, IWindowsSandboxHost host)
    {
        _options = options;
        _loggers = loggers;
        _runner = runner;
        _host = host;
    }

    public string Id => ProviderId;
    public LocalizedText DisplayName { get; } = new("Windows Sandbox", "Windows Sandbox");
    public bool IsDemo => false;

    public Task<ProviderAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken)
    {
        var checks = new List<ProviderCheck>();

        if (!OperatingSystem.IsWindows())
        {
            checks.Add(Check("os", new("Windows", "نظام Windows"), false,
                new("Windows Sandbox needs Windows 10 or 11. You can still explore Blazma with the demo analysis.", "يتطلب Windows Sandbox نظام Windows 10 أو 11. يمكنك تجربة Blazma عبر التحليل التجريبي.")));
            return Task.FromResult(new ProviderAvailability(ProviderReadiness.NotSupported, checks));
        }

        var buildOk = OperatingSystem.IsWindowsVersionAtLeast(10, 0, 18362);
        checks.Add(Check("os", new("Windows version", "إصدار Windows"), buildOk,
            buildOk ? new("Windows 10 1903 or later.", "Windows 10 1903 أو أحدث.") : new("Windows 10 version 1903 or later is required.", "يلزم Windows 10 إصدار 1903 أو أحدث.")));

        var featureOk = _host.SandboxExecutable is not null;
        var home = !featureOk && IsHomeEdition(ReadEditionId());
        checks.Add(Check("feature", new("Windows Sandbox feature", "ميزة Windows Sandbox"), featureOk,
            featureOk ? new("Installed.", "مثبتة.")
            : home ? new("This is Windows Home, which does not include Windows Sandbox. Use a VirtualBox virtual machine instead (Settings → Isolated environment), or upgrade to Windows Pro.",
                         "هذه نسخة Windows Home، ولا تتضمن Windows Sandbox. استخدم جهازًا افتراضيًا في VirtualBox بدلًا منه (الإعدادات ← البيئة المعزولة)، أو رقِّ إلى Windows Pro.")
                      : new("Turn on \"Windows Sandbox\" in Windows Features (optionalfeatures.exe), enable virtualization in firmware if asked, then restart.",
                            "فعّل \"Windows Sandbox\" من ميزات Windows ‏(optionalfeatures.exe)، وفعّل المحاكاة الافتراضية من BIOS إذا طُلب، ثم أعد التشغيل.")));

        var agentOk = File.Exists(Path.Combine(_options.AgentFolder, Contracts.Protocol.AgentExecutable));
        checks.Add(Check("agent", new("Monitoring agent", "وكيل المراقبة"), agentOk,
            agentOk ? new("Present.", "موجود.") : new("Blazma.Agent.exe was not found next to Blazma. Reinstall or build the agent (see README).", "لم يُعثر على Blazma.Agent.exe بجانب Blazma. أعد التثبيت أو ابنِ الوكيل (راجع README).")));

        var running = _host.RunningClients().Count > 0;
        checks.Add(Check("instance", new("No other sandbox running", "لا توجد بيئة معزولة أخرى قيد التشغيل"), !running,
            running ? new("Windows Sandbox is already open. Close it first; only one instance can run at a time.", "Windows Sandbox مفتوح بالفعل. أغلقه أولًا، إذ لا يمكن تشغيل أكثر من نسخة واحدة.") : new("Ready.", "جاهز.")));

        var readiness = !buildOk ? ProviderReadiness.NotSupported
            : checks.All(c => c.Passed) ? ProviderReadiness.Ready
            : running ? ProviderReadiness.Unavailable
            : ProviderReadiness.NeedsSetup;
        return Task.FromResult(new ProviderAvailability(readiness, checks));
    }

    public Task<ISandboxSession> CreateSessionAsync(SandboxSessionRequest request, CancellationToken cancellationToken)
    {
        ISandboxSession session = new WindowsSandboxSession(request, _options, _loggers?.CreateLogger<WindowsSandboxSession>() ?? NullLogger<WindowsSandboxSession>.Instance, _runner, _host);
        return Task.FromResult(session);
    }

    private static ProviderCheck Check(string id, LocalizedText label, bool passed, LocalizedText detail) => new(id, label, passed, detail);

    /// <summary>Home editions ("Core…") have no Windows Sandbox and cannot turn it on.</summary>
    internal static bool IsHomeEdition(string? editionId) =>
        editionId is not null && editionId.StartsWith("Core", StringComparison.OrdinalIgnoreCase);

    private static string? ReadEditionId()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return key?.GetValue("EditionID") as string;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }
}
