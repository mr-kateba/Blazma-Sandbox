using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Blazma.Storage;

public static class BlazmaJson
{
    /// <summary>Shared options for stored documents and JSON reports: stable, readable, enums as names.</summary>
    public static JsonSerializerOptions Options { get; } = Create(indented: false);

    public static JsonSerializerOptions Indented { get; } = Create(indented: true);

    private static JsonSerializerOptions Create(bool indented) => new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        // Never Populate: it would fill shared default instances in place (for example
        // RiskAssessment.Empty or RiskThresholds.Default) and leak values between documents.
        // Settings that need defaults merged in (shortcuts) are handled by SettingsStore.Migrate.
        WriteIndented = indented,
        // Reports are standalone files (never embedded in HTML), so keep Arabic and paths readable.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() },
        // Process trees nest two levels per process (node, children). The default of 64 made a run
        // whose sample spawned a chain of about 30 processes fail while saving; the graph keeps
        // chains to ProcessGraph.MaxTreeDepth (100) levels, which fits with room to spare.
        MaxDepth = 256,
    };
}
