using System.Globalization;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Rules;

/// <summary>YARA rules (the user's own or community packs) matched the sample, a dropped file or memory.</summary>
public sealed class YaraMatchRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-Y001",
        Version = "1.0",
        Name = new("Matched YARA signatures", "طابق تواقيع YARA"),
        Description = new("YARA rules from your rules folder matched this analysis. A rule is only as good as its author: check which rule matched and where before drawing conclusions.",
            "طابقت قواعد YARA من مجلد القواعد لديك هذا التحليل. دقة القاعدة من دقة كاتبها، فراجع أي قاعدة طابقت وأين قبل الاستنتاج."),
        Category = FindingCategory.Signature,
        Severity = Severity.High,
        Weight = 20,
        AttackTechniques = [],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var matches = (context.Static?.YaraMatches ?? [])
            .Concat(context.DroppedFiles.SelectMany(d => d.Static?.YaraMatches ?? []))
            .Concat(context.MemoryArtifacts.SelectMany(m => m.YaraMatches))
            .Take(50).ToList();
        if (matches.Count == 0) return null;

        var evidence = matches.GroupBy(m => (m.Rule, m.Target)).Select(g => g.First()).Take(25).Select(m => new Evidence
        {
            Kind = "yara",
            Description = m.Family is { } family
                ? new($"Rule {m.Rule} (family: {family}) matched {m.Target}", $"طابقت القاعدة {m.Rule} (العائلة: {family}) في {m.Target}")
                : new($"Rule {m.Rule} matched {m.Target}", $"طابقت القاعدة {m.Rule} في {m.Target}"),
            Technical = string.Join(", ", m.Strings.Take(5).Select(s => $"{s.Identifier}@0x{s.Offset:X}")) is { Length: > 0 } t ? $"{m.Source}: {t}" : m.Source,
        }).ToList();

        var families = matches.Select(m => m.Family).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var explanation = families.Count == 0 ? null : new Core.Text.LocalizedText(
            $"{Metadata.Description.En} Families named by the rules: {string.Join(", ", families)}.",
            $"{Metadata.Description.Ar} العائلات التي تسمّيها القواعد: {string.Join("، ", families)}.");
        return Build(evidence, explanation, severity: families.Count > 0 ? Severity.Critical : Severity.High);
    }
}

/// <summary>Code that is not backed by any file on disk: the classic sign of unpacking or injection.</summary>
public sealed class InjectedCodeRule : Rule
{
    /// <summary>Script engines and browsers compile code at run time, so executable private memory alone means little there.</summary>
    private static readonly HashSet<string> JitHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "msedge.exe", "chrome.exe", "firefox.exe", "java.exe", "javaw.exe", "node.exe", "dotnet.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    };

    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-V001",
        Version = "1.0",
        Name = new("Hidden program code in memory", "كود برنامج مخفي في الذاكرة"),
        Description = new("A process held executable code that does not come from any file on disk, often a whole program image. Packers and injected malware do this; a few legitimate protectors do too.",
            "احتفظت عملية بكود قابل للتنفيذ لا يأتي من أي ملف على القرص، وغالبًا يكون برنامجًا كاملًا. تفعل ذلك أدوات التغليف والبرمجيات الخبيثة المحقونة، وبعض أدوات الحماية المشروعة أيضًا."),
        Category = FindingCategory.Memory,
        Severity = Severity.High,
        Weight = 25,
        AttackTechniques = ["T1055", "T1027.002"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var strong = context.MemoryArtifacts.Where(m => m.HasPeHeader || m.Kind == MemoryRegionKind.UnbackedImage).ToList();
        var weak = context.MemoryArtifacts.Where(m => !strong.Contains(m) && m.Kind == MemoryRegionKind.ReadWriteExecute && !JitHosts.Contains(m.ProcessName)).ToList();
        var regions = strong.Concat(weak).Take(25).ToList();
        if (regions.Count == 0) return null;
        var evidence = regions.Select(m => new Evidence
        {
            Kind = "memory",
            Description = m.HasPeHeader
                ? new($"{m.ProcessName} holds a program image at 0x{m.BaseAddress:X} ({Size(m.Size)}, {m.Protection}) with no file behind it", $"يحمل {m.ProcessName} صورة برنامج عند 0x{m.BaseAddress:X} ({Size(m.Size)}، {m.Protection}) دون ملف خلفها")
                : new($"{m.ProcessName} has {m.Protection} memory at 0x{m.BaseAddress:X} ({Size(m.Size)})", $"لدى {m.ProcessName} ذاكرة {m.Protection} عند 0x{m.BaseAddress:X} ({Size(m.Size)})"),
            Technical = $"sha256 {m.Sha256}",
        }).ToList();
        // RWX memory without a program image is a weaker signal: report it, but let it count less.
        var finding = Build(evidence, severity: strong.Count > 0 ? Severity.High : Severity.Medium);
        return strong.Count > 0 || finding is null ? finding : finding with { Points = 8 };
    }

    private static string Size(long bytes) => bytes >= 1024 * 1024 ? $"{bytes / (1024.0 * 1024):0.#} MB" : $"{bytes / 1024.0:0.#} KB";
}

/// <summary>The sample tried to reach servers; the simulated internet answered instead of the real ones.</summary>
public sealed class SimulatedContactRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-N005",
        Version = "1.0",
        Name = new("Tried to reach internet servers", "حاول الوصول إلى خوادم على الإنترنت"),
        Description = new("Programs in the analyzed tree sent web or TLS requests. The simulated internet answered, so nothing left the sandbox, but the addresses show where it would have gone.",
            "أرسلت برامج ضمن شجرة التحليل طلبات ويب أو TLS. أجاب الإنترنت الوهمي، فلم يخرج شيء من البيئة المعزولة، لكن العناوين تكشف وجهتها."),
        Category = FindingCategory.Network,
        Severity = Severity.Medium,
        Weight = 10,
        AttackTechniques = ["T1071.001"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var hits = context.TreeEvents.Where(e => e.Action is EventAction.HttpRequest or EventAction.TlsHandshake)
            .GroupBy(e => Host(e)).Select(g => g.First()).Take(25).ToList();
        var evidence = hits.Select(e => EventEvidence("network", e, e.Action == EventAction.HttpRequest
            ? new($"{e.ProcessName} requested {e.Detail(DetailKeys.HttpMethod)} {e.Target}", $"طلب {e.ProcessName} ‏{e.Detail(DetailKeys.HttpMethod)} {e.Target}")
            : new($"{e.ProcessName} opened a TLS connection to {Host(e)}", $"فتح {e.ProcessName} اتصال TLS إلى {Host(e)}"))).ToList();
        return Build(evidence, processes: hits.Select(context.NodeOf).OfType<Core.Processes.ProcessNode>().Select(n => n.Key), firstSeen: hits.FirstOrDefault()?.RelativeTime);
    }

    private static string Host(AnalysisEvent e) => e.Detail(DetailKeys.HttpHost) ?? e.Detail(DetailKeys.ServerName) ?? e.Target ?? "?";
}

/// <summary>Data sent out in a request body: registration, beaconing or exfiltration.</summary>
public sealed class DataUploadRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-N006",
        Version = "1.0",
        Name = new("Sent data to a server", "أرسل بيانات إلى خادم"),
        Description = new("A request carried data out of the computer (for example machine or user details). Check the preview in the evidence to see what was sent.",
            "حمل طلبٌ بيانات إلى خارج الجهاز (مثل معلومات الجهاز أو المستخدم). راجع المعاينة في الأدلة لترى ما أُرسل."),
        Category = FindingCategory.Network,
        Severity = Severity.Medium,
        Weight = 12,
        AttackTechniques = ["T1041"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var uploads = context.TreeEvents.Where(e => e.Action == EventAction.HttpRequest
            && e.Detail(DetailKeys.HttpMethod) is "POST" or "PUT"
            && (e.Detail(DetailKeys.BodyPreview) is { Length: > 0 } || long.TryParse(e.Detail(DetailKeys.BytesSent), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) && n > 0))
            .Take(25).ToList();
        var evidence = uploads.Select(e => EventEvidence("network", e,
            new($"{e.ProcessName} sent data to {e.Target}", $"أرسل {e.ProcessName} بيانات إلى {e.Target}"),
            e.Detail(DetailKeys.BodyPreview) ?? e.Target)).ToList();
        return Build(evidence, processes: uploads.Select(context.NodeOf).OfType<Core.Processes.ProcessNode>().Select(n => n.Key), firstSeen: uploads.FirstOrDefault()?.RelativeTime);
    }
}

/// <summary>Hash reputation from services the user enabled. Known, not observed: kept clearly separate in the report.</summary>
public sealed class ReputationRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-R101",
        Version = "1.0",
        Name = new("Known to online reputation services", "معروف لدى خدمات السمعة على الإنترنت"),
        Description = new("Services you enabled already know this exact file (by its SHA-256). Only the hash was sent.",
            "تعرف الخدمات التي فعّلتها هذا الملف بعينه (عبر بصمته SHA-256). أُرسلت البصمة فقط."),
        Category = FindingCategory.Reputation,
        Severity = Severity.High,
        Weight = 30,
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var bad = context.Reputation.Where(r => r.Verdict is ReputationVerdict.Malicious or ReputationVerdict.Suspicious).ToList();
        if (bad.Count == 0) return null;
        var evidence = bad.Select(r => new Evidence
        {
            Kind = "reputation",
            Description = new(
                $"{r.ProviderName}: {r.Verdict}{(r.Detections is { } d ? $" ({d}/{r.Engines} engines)" : "")}{(r.Family is { } f ? $", family {f}" : "")}",
                $"{r.ProviderName}: {(r.Verdict == ReputationVerdict.Malicious ? "خبيث" : "مشبوه")}{(r.Detections is { } d2 ? $" ({d2}/{r.Engines} محركات)" : "")}{(r.Family is { } f2 ? $"، العائلة {f2}" : "")}"),
            Technical = r.Link,
        }).ToList();
        var malicious = bad.Any(r => r.Verdict == ReputationVerdict.Malicious);
        var finding = Build(evidence, severity: malicious ? Severity.High : Severity.Medium);
        return finding is null || malicious ? finding : finding with { Points = 10 };
    }
}

/// <summary>Several risky capabilities in the code at once. Potential only, so it counts little.</summary>
public sealed class CapabilitiesRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-S101",
        Version = "1.0",
        Name = new("Code can do several risky things", "الكود قادر على عدة أفعال خطرة"),
        Description = new("Reading the program without running it shows several abilities that are risky together (for example capturing keys and sending data). This is what it can do, not what it did.",
            "قراءة البرنامج دون تشغيله تكشف عدة قدرات خطرة مجتمعة (مثل التقاط المفاتيح وإرسال البيانات). هذا ما يستطيع فعله، لا ما فعله."),
        Category = FindingCategory.Static,
        Severity = Severity.Low,
        Weight = 6,
    };

    public override Finding? Evaluate(RuleContext context)
    {
        if (!context.UseCapabilities || context.Static is null) return null;
        var risky = context.Static.Capabilities.Where(c => c.Severity >= Severity.Medium).ToList();
        if (risky.Count < 3) return null;
        var evidence = risky.Take(15).Select(c => new Evidence
        {
            Kind = "capability",
            Description = c.Name,
            Technical = string.Join("; ", c.Evidence.Take(4)),
        }).ToList();
        var techniques = risky.SelectMany(c => c.AttackTechniques).Distinct(StringComparer.OrdinalIgnoreCase).Take(20).ToList();
        return Build(evidence, severity: risky.Count(c => c.Severity >= Severity.High) >= 2 ? Severity.Medium : Severity.Low) is { } f ? f with { AttackTechniques = techniques } : null;
    }
}

/// <summary>Wallet addresses, bot tokens, webhooks and onion addresses: rare in normal software, common in stealers and ransomware.</summary>
public sealed class EmbeddedSecretsRule : Rule
{
    private static readonly ArtifactKind[] Kinds =
    [
        ArtifactKind.BitcoinAddress, ArtifactKind.EthereumAddress, ArtifactKind.MoneroAddress,
        ArtifactKind.TelegramBotToken, ArtifactKind.DiscordWebhook, ArtifactKind.OnionAddress,
    ];

    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-S102",
        Version = "1.0",
        Name = new("Contains wallet addresses or bot tokens", "يحتوي عناوين محافظ أو رموز بوتات"),
        Description = new("Cryptocurrency wallets, Telegram/Discord bot credentials or Tor addresses were found in the file, a dropped file or memory. Stealers and ransomware use these to get paid or to send stolen data.",
            "وُجدت عناوين محافظ عملات رقمية أو بيانات بوتات تيليجرام/ديسكورد أو عناوين Tor في الملف أو ملف أنشأه أو في الذاكرة. تستخدمها برامج السرقة والفدية لتلقي المال أو إرسال البيانات المسروقة."),
        Category = FindingCategory.Static,
        Severity = Severity.Medium,
        Weight = 8,
        AttackTechniques = ["T1102", "T1657"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var found = context.Artifacts.Where(a => Kinds.Contains(a.Kind)).Take(15).ToList();
        var evidence = found.Select(a => new Evidence
        {
            Kind = "artifact",
            Description = new($"{a.Kind} in {a.Source}", $"{a.Kind} في {a.Source}"),
            Technical = a.Kind is ArtifactKind.TelegramBotToken or ArtifactKind.DiscordWebhook ? Mask(a.Value) : a.Value,
        }).ToList();
        return Build(evidence);
    }

    /// <summary>Tokens are credentials: show enough to recognise them, not enough to use them.</summary>
    private static string Mask(string value) => value.Length <= 16 ? "***" : value[..10] + "…" + value[^4..];
}
