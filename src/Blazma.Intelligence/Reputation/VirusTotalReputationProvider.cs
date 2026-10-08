using System.Net;
using System.Text.Json;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Settings;
using Blazma.Core.Text;
using Blazma.Intelligence.Net;

namespace Blazma.Intelligence.Reputation;

/// <summary>
/// VirusTotal file report (API v3, <c>GET /api/v3/files/{sha256}</c> with the <c>x-apikey</c>
/// header). Only the hash is sent; the file is never uploaded.
/// </summary>
public sealed class VirusTotalReputationProvider : HashReputationProvider
{
    public const string ProviderId = "virustotal";

    /// <summary>At least this many engines saying "malicious" makes the verdict Malicious.</summary>
    public const int MaliciousThreshold = 5;

    /// <summary>At least this many "suspicious" (with no "malicious") makes the verdict Suspicious.</summary>
    public const int SuspiciousThreshold = 3;

    private static readonly LocalizedText Name = new("VirusTotal", "فايروس توتال (VirusTotal)");
    private readonly Func<IntegrationSettings> _settings;

    /// <param name="settings">Read on every call, so changes in Settings apply without a restart.</param>
    public VirusTotalReputationProvider(HttpClient httpClient, Func<IntegrationSettings> settings, ISecretProtector secrets, ReputationProviderOptions? options = null, TimeProvider? time = null)
        : base(httpClient, secrets, options, time)
    {
        ArgumentNullException.ThrowIfNull(settings);
        _settings = settings;
    }

    public VirusTotalReputationProvider(HttpClient httpClient, IntegrationSettings settings, ISecretProtector secrets, ReputationProviderOptions? options = null, TimeProvider? time = null)
        : this(httpClient, () => settings, secrets, options, time)
    {
    }

    public override string Id => ProviderId;
    public override LocalizedText DisplayName => Name;
    protected override string ServiceName => "VirusTotal";
    protected override bool IsEnabled => _settings().VirusTotalEnabled;
    protected override string? StoredApiKey => _settings().VirusTotalApiKey;

    public static string LinkFor(string sha256) => $"https://www.virustotal.com/gui/file/{sha256.ToLowerInvariant()}";

    protected override HttpRequestMessage CreateRequest(string sha256, string apiKey)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"https://www.virustotal.com/api/v3/files/{sha256}"));
        request.Headers.TryAddWithoutValidation("x-apikey", apiKey);
        request.Headers.Accept.ParseAdd("application/json");
        return request;
    }

    protected override ReputationResult Interpret(HttpStatusCode status, JsonElement? json, string sha256)
    {
        if (status == HttpStatusCode.NotFound) return Result(ReputationVerdict.NotFound);
        if (status != HttpStatusCode.OK) return Failed($"VirusTotal returned HTTP {(int)status}.");
        if (json is not { } root || SafeText.Object(root, "data") is not { } data || SafeText.Object(data, "attributes") is not { } attributes)
            return Failed("VirusTotal sent a response Blazma could not read.");

        int? detections = null, engines = null;
        var verdict = ReputationVerdict.Unknown;
        if (SafeText.Object(attributes, "last_analysis_stats") is { } stats)
        {
            var malicious = Count(stats, "malicious");
            var suspicious = Count(stats, "suspicious");
            // Engines that reached a verdict on this file. Timeouts, failures and unsupported types are not counted.
            var analyzed = (long)malicious + suspicious + Count(stats, "undetected") + Count(stats, "harmless");
            detections = (int)Math.Min((long)malicious + suspicious, int.MaxValue);
            engines = (int)Math.Min(analyzed, int.MaxValue);
            verdict = malicious >= MaliciousThreshold ? ReputationVerdict.Malicious
                : malicious >= 1 || suspicious >= SuspiciousThreshold ? ReputationVerdict.Suspicious
                : analyzed > 0 ? ReputationVerdict.Clean
                : ReputationVerdict.Unknown;
        }

        var family = SafeText.Object(attributes, "popular_threat_classification") is { } ptc
            ? SafeText.CleanOrNull(SafeText.String(ptc, "suggested_threat_label"), 128)
            : null;

        DateTimeOffset? firstSeen = SafeText.Integer(attributes, "first_submission_date") is { } unix && unix is > 0 and < 253_402_300_800
            ? DateTimeOffset.FromUnixTimeSeconds(unix)
            : null;

        return Result(verdict) with
        {
            Detections = detections,
            Engines = engines,
            Family = family,
            Tags = SafeText.Strings(SafeText.Array(attributes, "tags"), 30, 64),
            FirstSeen = firstSeen,
            Link = LinkFor(sha256),
        };
    }

    private static int Count(JsonElement stats, string name) =>
        SafeText.Integer(stats, name) is { } n ? (int)Math.Clamp(n, 0, int.MaxValue) : 0;
}
