using System.Diagnostics;
using Blazma.Core.Abstractions;
using Blazma.Sandbox.Channel;
using Blazma.Core.Text;
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
    public TimeSpan HeartbeatTimeout { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan AgentHelloTimeout { get; init; } = TimeSpan.FromMinutes(3);
    public bool StopWhenTreeExits { get; init; } = true;
    public AgentLimits AgentLimits { get; init; } = AgentLimits.Default;
}

/// <summary>
/// Runs samples in Windows Sandbox: a disposable, hardware-virtualised Windows instance
/// that is wiped when it closes. Requires Windows 10/11 Pro, Enterprise or Education with
/// the "Windows Sandbox" feature enabled and virtualisation turned on in firmware.
/// </summary>
public sealed class WindowsSandboxProvider(WindowsSandboxOptions options, ILoggerFactory? loggers = null) : ISandboxProvider
{
    public const string ProviderId = "windows-sandbox";
    internal static readonly string[] SandboxProcessNames = ["WindowsSandbox", "WindowsSandboxClient", "WindowsSandboxRemoteSession", "WindowsSandboxServer"];

    public string Id => ProviderId;
    public LocalizedText DisplayName { get; } = new("Windows Sandbox", "Windows Sandbox");
    public bool IsDemo => false;

    public static string SandboxExecutable => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsSandbox.exe");

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

        var featureOk = File.Exists(SandboxExecutable);
        checks.Add(Check("feature", new("Windows Sandbox feature", "ميزة Windows Sandbox"), featureOk,
            featureOk ? new("Installed.", "مثبتة.")
                      : new("Turn on \"Windows Sandbox\" in Windows Features (optionalfeatures.exe), enable virtualization in firmware if asked, then restart.",
                            "فعّل \"Windows Sandbox\" من ميزات Windows ‏(optionalfeatures.exe)، وفعّل المحاكاة الافتراضية من BIOS إذا طُلب، ثم أعد التشغيل.")));

        var agentOk = File.Exists(Path.Combine(options.AgentFolder, Contracts.Protocol.AgentExecutable));
        checks.Add(Check("agent", new("Monitoring agent", "وكيل المراقبة"), agentOk,
            agentOk ? new("Present.", "موجود.") : new("Blazma.Agent.exe was not found next to Blazma. Reinstall or build the agent (see README).", "لم يُعثر على Blazma.Agent.exe بجانب Blazma. أعد التثبيت أو ابنِ الوكيل (راجع README).")));

        var running = SandboxProcessNames.Any(n => Process.GetProcessesByName(n).Length > 0);
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
        ISandboxSession session = new WindowsSandboxSession(request, options, loggers?.CreateLogger<WindowsSandboxSession>() ?? NullLogger<WindowsSandboxSession>.Instance);
        return Task.FromResult(session);
    }

    private static ProviderCheck Check(string id, LocalizedText label, bool passed, LocalizedText detail) => new(id, label, passed, detail);
}
