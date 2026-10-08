using System.Text.Json;
using Blazma.Core.Settings;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blazma.Storage;

/// <summary>
/// Loads and saves the user's settings. Writes are atomic (temp file + rename). A corrupt
/// file is kept as a backup and replaced with defaults instead of crashing the app.
/// </summary>
public sealed class SettingsStore(BlazmaPaths paths, ILogger<SettingsStore>? logger = null) : IDisposable
{
    private readonly ILogger _logger = logger ?? NullLogger<SettingsStore>.Instance;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public void Dispose() => _gate.Dispose();

    public BlazmaSettings Load()
    {
        try
        {
            if (!File.Exists(paths.Settings)) return new BlazmaSettings();
            var settings = JsonSerializer.Deserialize<BlazmaSettings>(File.ReadAllText(paths.Settings), BlazmaJson.Options) ?? new BlazmaSettings();
            return Migrate(settings);
        }
        catch (Exception ex) when (ex is JsonException or IOException or NotSupportedException)
        {
            _logger.LogWarning(ex, "Settings file was unreadable; keeping a backup and using defaults");
            try { File.Copy(paths.Settings, paths.Settings + ".corrupt", overwrite: true); } catch (IOException) { }
            return new BlazmaSettings();
        }
    }

    public async Task SaveAsync(BlazmaSettings settings, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(paths.Settings)!);
            var temp = paths.Settings + ".tmp";
            await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(settings, BlazmaJson.Indented), cancellationToken).ConfigureAwait(false);
            File.Move(temp, paths.Settings, overwrite: true);
        }
        finally
        {
            _gate.Release();
        }
    }

    private static BlazmaSettings Migrate(BlazmaSettings s)
    {
        // Version 1 is the first schema. Future migrations go here, one step per version.
        s.Version = BlazmaSettings.CurrentVersion;
        s.Detection.RuleOverrides = new Dictionary<string, RuleOverride>(s.Detection.RuleOverrides, StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in ShortcutSettings.Defaults) s.Shortcuts.Bindings.TryAdd(k, v);
        if (!s.Detection.Thresholds.IsValid) s.Detection.Thresholds = Core.Findings.RiskThresholds.Default;
        s.Appearance.UiScalePercent = s.Appearance.ClampedScale;
        return s;
    }
}
