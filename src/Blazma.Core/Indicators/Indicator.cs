namespace Blazma.Core.Indicators;

public enum IndicatorType
{
    Sha256,
    Domain,
    IpAddress,
    Url,
    FilePath,
    RegistryKey,
    ProcessName,
    PersistenceArtifact,
}

/// <summary>
/// No indicator is called malicious by default. Status only rises above
/// <see cref="Observed"/> when a finding with evidence refers to it, or when the user's
/// own watchlist names it.
/// </summary>
public enum IndicatorStatus
{
    Informational,
    Observed,
    Suspicious,
    HighRisk,
    WatchlistMatch,
    KnownReputation,
}

public sealed record Indicator(IndicatorType Type, string Value, IndicatorStatus Status, string Source, IReadOnlyList<long> EventSequences)
{
    public string? Note { get; init; }
}
