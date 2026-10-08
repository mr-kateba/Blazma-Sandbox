using Blazma.Core.Findings;
using Blazma.Core.Settings;
using Blazma.Storage;

namespace Blazma.App.Tests;

public sealed class SettingsTests : IDisposable
{
    private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory("blz-settings");
    public void Dispose() => _dir.Delete(true);

    [Fact]
    public async Task Customisations_survive_a_round_trip()
    {
        var store = new SettingsStore(new BlazmaPaths(_dir.FullName));
        var s = store.Load();
        s.Appearance.Theme = ThemeVariant.Midnight;
        s.Appearance.Accent = AccentColor.Teal;
        s.Appearance.UiScalePercent = 115;
        s.Detection.Thresholds = new RiskThresholds(15, 40, 70);
        s.Detection.RuleOverrides["BLZ-E001"] = new RuleOverride { Enabled = false };
        s.Detection.Watchlist.Add(new WatchlistEntry(WatchlistEntryType.Domain, "*.bad.example"));
        s.Shortcuts.Bindings["NewAnalysis"] = "Ctrl+Shift+N";
        await store.SaveAsync(s);

        var loaded = store.Load();
        Assert.Equal(ThemeVariant.Midnight, loaded.Appearance.Theme);
        Assert.Equal(AccentColor.Teal, loaded.Appearance.Accent);
        Assert.Equal(115, loaded.Appearance.UiScalePercent);
        Assert.Equal(new RiskThresholds(15, 40, 70), loaded.Detection.Thresholds);
        Assert.False(loaded.Detection.RuleOverrides["blz-e001"].Enabled);
        Assert.Single(loaded.Detection.Watchlist);
        Assert.Equal("Ctrl+Shift+N", loaded.Shortcuts.Get("NewAnalysis"));
    }

    [Fact]
    public void Corrupt_settings_fall_back_to_safe_defaults_and_are_kept_as_backup()
    {
        var paths = new BlazmaPaths(_dir.FullName);
        File.WriteAllText(paths.Settings, "{ this is not json");
        var s = new SettingsStore(paths).Load();
        Assert.Equal(ThemeVariant.Dark, s.Appearance.Theme);
        Assert.True(File.Exists(paths.Settings + ".corrupt"));
    }

    [Fact]
    public void Defaults_are_the_safe_choices()
    {
        var s = new BlazmaSettings();
        Assert.True(s.Privacy.RedactExports);
        Assert.False(s.Privacy.CommunitySharingEnabled);
        Assert.False(s.Ai.Enabled);
        Assert.Equal(AccentColor.BlazmaOrange, s.Appearance.Accent);
        Assert.Equal(Core.Analysis.NetworkPolicy.Disabled, new Core.Analysis.AnalysisOptions().Network);
        Assert.False(new Core.Analysis.AnalysisOptions().CaptureScreenshots);
    }

    [Fact]
    public void Invalid_thresholds_from_disk_are_repaired()
    {
        var paths = new BlazmaPaths(_dir.FullName);
        var store = new SettingsStore(paths);
        var s = new BlazmaSettings();
        s.Detection.Thresholds = new RiskThresholds(80, 50, 20);
        store.SaveAsync(s).GetAwaiter().GetResult();
        Assert.Equal(RiskThresholds.Default, store.Load().Detection.Thresholds);
    }
}
