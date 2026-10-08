namespace Blazma.Core.Analysis;

public enum NetworkPolicy
{
    /// <summary>No network inside the sandbox. DNS attempts are still observed.</summary>
    Disabled,

    /// <summary>The sandbox can reach the internet. Reduces isolation; requires explicit consent.</summary>
    Enabled,

    /// <summary>
    /// Still no real network, but the agent answers inside the sandbox: names resolve to a
    /// local fake server that records HTTP requests and TLS server names. Default.
    /// </summary>
    Simulated,
}

/// <summary>What one analysis run captures and for how long.</summary>
public sealed record AnalysisOptions
{
    public TimeSpan Duration { get; init; } = TimeSpan.FromMinutes(2);
    public NetworkPolicy Network { get; init; } = NetworkPolicy.Disabled;
    public bool CaptureProcesses { get; init; } = true;
    public bool CaptureFiles { get; init; } = true;
    public bool CaptureRegistry { get; init; } = true;
    public bool CaptureNetwork { get; init; } = true;
    public bool TakeSnapshots { get; init; } = true;

    /// <summary>Screenshots of the sandbox desktop (never of the host).</summary>
    public bool CaptureScreenshots { get; init; } = true;
    public int ScreenshotIntervalSeconds { get; init; } = 5;

    /// <summary>The analyst can use the sandbox window during the run; the run does not end early and can be extended.</summary>
    public bool Interactive { get; init; }

    /// <summary>Move the mouse and press the usual installer buttons (Next, I agree, Install).</summary>
    public bool SimulateUser { get; init; } = true;

    /// <summary>Copy files the sample creates out of the sandbox for analysis.</summary>
    public bool CollectDroppedFiles { get; init; } = true;

    /// <summary>Dump suspicious memory regions (unpacked or injected code) at the end of the run.</summary>
    public bool DumpMemory { get; init; } = true;

    /// <summary>Record network traffic with Windows' built-in pktmon. Only meaningful with the real network enabled.</summary>
    public bool CapturePcap { get; init; }

    public string ProfileId { get; init; } = AnalysisProfile.StandardId;

    public static readonly TimeSpan MinDuration = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan MaxDuration = TimeSpan.FromMinutes(30);

    public AnalysisOptions Normalized() => this with
    {
        Duration = Duration < MinDuration ? MinDuration : Duration > MaxDuration ? MaxDuration : Duration,
        ScreenshotIntervalSeconds = Math.Clamp(ScreenshotIntervalSeconds, 2, 60),
        CapturePcap = CapturePcap && Network == NetworkPolicy.Enabled,
        SimulateUser = SimulateUser && !Interactive,
    };
}

/// <summary>A named, reusable set of options. Built-in profiles cannot be edited; users can add their own.</summary>
public sealed record AnalysisProfile(string Id, string NameEn, string NameAr, AnalysisOptions Options, bool BuiltIn)
{
    public const string QuickId = "quick";
    public const string StandardId = "standard";
    public const string DeepId = "deep";
    public const string InteractiveId = "interactive";

    public static IReadOnlyList<AnalysisProfile> BuiltIns { get; } =
    [
        new(QuickId, "Quick", "سريع", new AnalysisOptions { Duration = TimeSpan.FromSeconds(60), ProfileId = QuickId, TakeSnapshots = false, DumpMemory = false, Network = NetworkPolicy.Simulated }, true),
        new(StandardId, "Standard", "قياسي", new AnalysisOptions { Duration = TimeSpan.FromMinutes(2), ProfileId = StandardId, Network = NetworkPolicy.Simulated }, true),
        new(DeepId, "Deep", "معمّق", new AnalysisOptions { Duration = TimeSpan.FromMinutes(5), ProfileId = DeepId, Network = NetworkPolicy.Simulated, ScreenshotIntervalSeconds = 3 }, true),
        new(InteractiveId, "Interactive", "تفاعلي", new AnalysisOptions { Duration = TimeSpan.FromMinutes(10), ProfileId = InteractiveId, Network = NetworkPolicy.Simulated, Interactive = true, SimulateUser = false }, true),
    ];
}
