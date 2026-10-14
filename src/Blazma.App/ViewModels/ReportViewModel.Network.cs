using System.Collections.ObjectModel;
using System.Globalization;
using Blazma.Analysis.Engine;
using Blazma.App.Localization;
using Blazma.App.Services;
using Blazma.Core.Analysis;

namespace Blazma.App.ViewModels;

/// <summary>One row of «Addresses the program tried to reach». The status has its own shape as well as a colour.</summary>
public sealed class DestinationRow(NetworkDestination d, HostResolution? resolved)
{
    public NetworkDestination Destination { get; } = d;
    public string Address { get; } = d.Address ?? "—";
    public bool HasAddress => Destination.Address is not null;

    /// <summary>What to copy: the address, or the domain when only a name is known.</summary>
    public string CopyText { get; } = d.Address ?? d.Domain ?? string.Empty;

    public string Port { get; } = d.Port?.ToString(CultureInfo.InvariantCulture) ?? "—";
    public string Protocol { get; } = d.Protocol;
    public string Domain { get; } = d.Domain ?? "—";
    public string Process { get; } = d.Processes.Count == 0 ? "?" : string.Join(", ", d.Processes);
    public string Count { get; } = "×" + d.Count.ToString(CultureInfo.InvariantCulture);
    public string Time { get; } = Fmt.Relative(d.FirstSeen);
    public string Data { get; } = d.BytesSent == 0 && d.BytesReceived == 0 ? "—" : $"↑{Fmt.Size(d.BytesSent)} ↓{Fmt.Size(d.BytesReceived)}";

    public string StatusText { get; } = Loc.T("DestStatus" + d.Status);

    /// <summary>The reason of a failure, or where the name came from.</summary>
    public string StatusDetail { get; } = d.Status switch
    {
        DestinationStatus.Failed => NetworkDestinations.DescribeError(d.ErrorCode).Get(Loc.Instance.Code),
        _ when d.DirectIp => Loc.T("DestDirectIp"),
        _ => string.Empty,
    };

    public bool HasStatusDetail => StatusDetail.Length > 0;

    /// <summary>Addresses looked up from this computer after the analysis (opt-in), clearly labelled as such.</summary>
    public string ResolvedLater { get; } = resolved is { Addresses.Count: > 0 } r ? Loc.F("DestResolvedLater", string.Join(", ", r.Addresses.Take(4))) : string.Empty;

    public bool HasResolvedLater => ResolvedLater.Length > 0;

    public bool IsConnected => Destination.Status == DestinationStatus.Connected;
    public bool IsSimulated => Destination.Status == DestinationStatus.Simulated;
    public bool IsFailed => Destination.Status == DestinationStatus.Failed;
    public bool IsAttempted => Destination.Status == DestinationStatus.Attempted;
    public bool IsLookupOnly => Destination.Status == DestinationStatus.LookupOnly;
}

public sealed record HostResolutionRow(string Domain, string Result, bool Resolved);

public sealed partial class ReportViewModel
{
    public ObservableCollection<DestinationRow> Destinations { get; } = [];
    public ObservableCollection<HostResolutionRow> HostResolutions { get; } = [];

    public bool HasDestinations => Destinations.Count > 0;
    public bool HasNoDestinations => Destinations.Count == 0;
    public bool HasHostResolutions => HostResolutions.Count > 0;

    /// <summary>Why the table can be empty, for the network mode this analysis used.</summary>
    public string DestinationsEmptyText => Result?.Options.Network switch
    {
        NetworkPolicy.Disabled => Loc.T("DestEmptyOffline"),
        NetworkPolicy.Simulated => Loc.T("DestEmptySimulated"),
        _ => Loc.T("DestEmptyOnline"),
    };

    private void BuildDestinations()
    {
        var r = Result!;
        // Reports saved before destinations were stored: derive them from the stored events.
        var list = r.NetworkDestinations.Count > 0 || r.Events.Count == 0
            ? r.NetworkDestinations
            : NetworkDestinations.Build(r.Events, ProcessGraph.Build(r.Events), NetworkMap.Build(r.Events));
        var resolved = r.HostResolutions.GroupBy(h => h.Domain, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        Destinations.Clear();
        foreach (var d in list)
            Destinations.Add(new DestinationRow(d, d.Domain is { } name && resolved.TryGetValue(name, out var h) ? h : null));

        HostResolutions.Clear();
        foreach (var h in r.HostResolutions)
            HostResolutions.Add(new HostResolutionRow(h.Domain, h.Addresses.Count > 0 ? string.Join(", ", h.Addresses) : h.Error ?? Loc.T("DestNotResolved"), h.Addresses.Count > 0));

        foreach (var name in new[] { nameof(HasDestinations), nameof(HasNoDestinations), nameof(HasHostResolutions), nameof(DestinationsEmptyText) })
            OnPropertyChanged(name);
    }
}
