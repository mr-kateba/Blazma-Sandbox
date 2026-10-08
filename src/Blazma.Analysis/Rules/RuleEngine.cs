using Blazma.Core.Findings;
using Blazma.Core.Settings;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blazma.Analysis.Rules;

/// <summary>Runs every enabled rule, applies the user's per-rule overrides and isolates rule failures.</summary>
public sealed class RuleEngine
{
    private readonly List<IRule> _rules;
    private readonly ILogger _logger;

    public RuleEngine(IEnumerable<IRule> rules, ILogger<RuleEngine>? logger = null)
    {
        _rules = rules.GroupBy(r => r.Metadata.Id, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).ToList();
        _logger = logger ?? NullLogger<RuleEngine>.Instance;
    }

    public IReadOnlyList<IRule> Rules => _rules;

    public static IReadOnlyList<IRule> BuiltInRules() =>
    [
        new StartupPersistenceRule(),
        new ScheduledTaskRule(),
        new ServiceInstallRule(),
        new SystemHijackRule(),
        new ScriptEngineRule(),
        new ObfuscatedCommandRule(),
        new ProxyExecutionRule(),
        new ShadowCopyDeletionRule(),
        new DroppedExecutableRule(),
        new DroppedFileExecutedRule(),
        new MassFileModificationRule(),
        new SelfDeletionRule(),
        new SecurityTamperingRule(),
        new NetworkRedirectionRule(),
        new ExternalConnectionRule(),
        new DroppedProcessNetworkRule(),
        new UnusualPortRule(),
        new DnsActivityRule(),
        new UnsignedSampleRule(),
        new PackedSampleRule(),
        new InjectionCapabilityRule(),
        new MonitoringInterruptedRule(),
        new FullChainRule(),
        new WatchlistRule(),
        new YaraMatchRule(),
        new InjectedCodeRule(),
        new SimulatedContactRule(),
        new DataUploadRule(),
        new ReputationRule(),
        new CapabilitiesRule(),
        new EmbeddedSecretsRule(),
    ];

    /// <summary>Loads *.json rule packs from a folder. Bad packs are reported, never fatal.</summary>
    public static (IReadOnlyList<IRule> Rules, IReadOnlyList<string> Errors) LoadRulePacks(string folder)
    {
        var rules = new List<IRule>();
        var errors = new List<string>();
        if (!Directory.Exists(folder)) return (rules, errors);
        foreach (var file in Directory.EnumerateFiles(folder, "*.json").Order().Take(64))
        {
            try
            {
                if (new FileInfo(file).Length > 1024 * 1024) { errors.Add($"{Path.GetFileName(file)}: larger than 1 MB, skipped"); continue; }
                var (packRules, packErrors) = JsonRulePack.Load(File.ReadAllText(file), Path.GetFileName(file));
                rules.AddRange(packRules);
                errors.AddRange(packErrors);
            }
            catch (IOException ex)
            {
                errors.Add($"{Path.GetFileName(file)}: {ex.Message}");
            }
        }
        return (rules, errors);
    }

    public IReadOnlyList<Finding> Evaluate(RuleContext context, IReadOnlyDictionary<string, RuleOverride> overrides)
    {
        var findings = new List<Finding>();
        foreach (var rule in _rules)
        {
            overrides.TryGetValue(rule.Metadata.Id, out var ov);
            if (ov is { Enabled: false }) continue;
            try
            {
                var finding = rule.Evaluate(context);
                if (finding is null || finding.Evidence.Count == 0) continue;
                if (ov?.Weight is { } w) finding = finding with { Points = Math.Clamp(w, 0, 50) };
                findings.Add(finding);
            }
            catch (Exception ex)
            {
                // A broken rule must never take the whole analysis down.
                _logger.LogError(ex, "Rule {RuleId} failed and was skipped", rule.Metadata.Id);
            }
        }
        return findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.Points).ToList();
    }
}
