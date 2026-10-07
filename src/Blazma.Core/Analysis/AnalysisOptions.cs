namespace Blazma.Core.Analysis;

public enum NetworkPolicy
{
    /// <summary>No network inside the sandbox. DNS attempts are still observed. Default.</summary>
    Disabled,

    /// <summary>The sandbox can reach the internet. Reduces isolation; requires explicit consent.</summary>
    Enabled,
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

    /// <summary>Planned. Disabled until a capture path exists that cannot leak host content.</summary>
    public bool CaptureScreenshots { get; init; }

    public string ProfileId { get; init; } = AnalysisProfile.StandardId;

    public static readonly TimeSpan MinDuration = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan MaxDuration = TimeSpan.FromMinutes(30);

    public AnalysisOptions Normalized() => this with
    {
        Duration = Duration < MinDuration ? MinDuration : Duration > MaxDuration ? MaxDuration : Duration,
        CaptureScreenshots = false,
    };
}

/// <summary>A named, reusable set of options. Built-in profiles cannot be edited; users can add their own.</summary>
public sealed record AnalysisProfile(string Id, string NameEn, string NameAr, AnalysisOptions Options, bool BuiltIn)
{
    public const string QuickId = "quick";
    public const string StandardId = "standard";
    public const string DeepId = "deep";

    public static IReadOnlyList<AnalysisProfile> BuiltIns { get; } =
    [
        new(QuickId, "Quick", "سريع", new AnalysisOptions { Duration = TimeSpan.FromSeconds(60), ProfileId = QuickId, TakeSnapshots = false }, true),
        new(StandardId, "Standard", "قياسي", new AnalysisOptions { Duration = TimeSpan.FromMinutes(2), ProfileId = StandardId }, true),
        new(DeepId, "Deep", "معمّق", new AnalysisOptions { Duration = TimeSpan.FromMinutes(5), ProfileId = DeepId }, true),
    ];
}
