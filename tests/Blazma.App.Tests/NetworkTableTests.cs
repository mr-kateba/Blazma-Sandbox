using Blazma.App.Localization;
using Blazma.App.ViewModels;
using Blazma.Core.Analysis;
using Blazma.Core.Settings;

namespace Blazma.App.Tests;

public class NetworkTableTests
{
    [Fact]
    public void Every_destination_status_has_a_label_in_both_languages()
    {
        foreach (var language in new[] { AppLanguage.English, AppLanguage.Arabic })
        {
            var keys = Loc.Instance.Keys(language).ToHashSet();
            Assert.All(Enum.GetNames<DestinationStatus>(), n => Assert.Contains("DestStatus" + n, keys));
        }
    }

    [Fact]
    public void Rows_show_the_name_for_simulated_traffic_and_the_reason_for_failures()
    {
        Loc.Instance.SetLanguage(AppLanguage.English);
        var simulated = new DestinationRow(new NetworkDestination { Domain = "c2.example.net", Port = 443, Protocol = "HTTPS", Status = DestinationStatus.Simulated, Count = 2, Processes = ["setup.exe"] },
            new HostResolution { Domain = "c2.example.net", Status = HostResolutionStatus.Resolved, Addresses = ["198.51.100.4"] });
        Assert.Equal("—", simulated.Address);
        Assert.Equal("c2.example.net", simulated.Domain);
        Assert.Equal("c2.example.net", simulated.CopyText);
        Assert.True(simulated.IsSimulated);
        Assert.False(simulated.IsFailed);
        Assert.Contains("198.51.100.4", simulated.ResolvedLater, StringComparison.Ordinal);
        Assert.Contains("after the analysis", simulated.ResolvedLater, StringComparison.Ordinal);

        var failed = new DestinationRow(new NetworkDestination { Address = "192.0.2.77", Port = 8443, Status = DestinationStatus.Failed, ErrorCode = "0xC000023C", Count = 6, DirectIp = true, BytesSent = 0 }, null);
        Assert.Equal("192.0.2.77", failed.CopyText);
        Assert.Equal("×6", failed.Count);
        Assert.Equal("—", failed.Data);
        Assert.Contains("No network", failed.StatusDetail, StringComparison.Ordinal);
        Assert.Equal(Loc.T("DestStatusFailed"), failed.StatusText);
        Assert.False(failed.HasResolvedLater);
    }

    [Fact]
    public void The_lookup_setting_is_off_by_default()
    {
        Assert.False(new BlazmaSettings().Integrations.ResolveContactedDomains);
    }
}
