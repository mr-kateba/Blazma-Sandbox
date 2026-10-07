using Blazma.Analysis.Engine;
using Blazma.Analysis.Static;
using Blazma.Analysis.Text;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Processes;
using Blazma.Core.Samples;
using Blazma.Core.Settings;
using Blazma.Core.Text;

namespace Blazma.Analysis.Rules;

public sealed class ExternalConnectionRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-N001",
        Version = "1.0",
        Name = new("Contacted an external endpoint", "اتصل بعنوان خارجي"),
        Description = new("A process in the analyzed tree opened a connection to an address on the internet. Most software does this (updates, licensing); it matters most combined with other behaviour.", "فتحت عملية ضمن شجرة التحليل اتصالًا بعنوان على الإنترنت. أغلب البرامج تفعل ذلك (تحديثات وتراخيص)، وتزداد أهميته عند اجتماعه مع سلوكيات أخرى."),
        Category = FindingCategory.Network,
        Severity = Severity.Medium,
        Weight = 10,
        AttackTechniques = ["T1071"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var connects = context.TreeEvents.Where(e => e.Action == EventAction.NetworkConnect && NetworkMap.IsExternal(e))
            .GroupBy(NetworkMap.Endpoint).Select(g => g.First()).Take(25).ToList();
        var evidence = connects.Select(e =>
        {
            var domain = context.Network.DomainFor(e.Detail(DetailKeys.RemoteAddress));
            var endpoint = NetworkMap.Endpoint(e);
            return EventEvidence("network", e,
                new($"{e.ProcessName} connected to {domain ?? endpoint}", $"اتصل {e.ProcessName} بـ {domain ?? endpoint}"),
                domain is null ? endpoint : $"{domain} → {endpoint}");
        }).ToList();
        return Build(evidence, firstSeen: connects.FirstOrDefault()?.RelativeTime);
    }
}

public sealed class UnusualPortRule : Rule
{
    private static readonly HashSet<int> CommonPorts = [80, 443, 53, 8080, 8443, 123];

    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-N003",
        Version = "1.0",
        Name = new("Used an uncommon network port", "استخدم منفذ شبكة غير شائع"),
        Description = new("An external connection used a port other than the usual web ports. This is unusual for everyday software.", "استخدم اتصال خارجي منفذًا غير منافذ الويب المعتادة، وهذا غير مألوف في البرامج اليومية."),
        Category = FindingCategory.Network,
        Severity = Severity.Low,
        Weight = 6,
        AttackTechniques = ["T1571"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var hits = context.TreeEvents.Where(e => e.Action == EventAction.NetworkConnect && NetworkMap.IsExternal(e)
                && int.TryParse(e.Detail(DetailKeys.RemotePort), out var port) && !CommonPorts.Contains(port))
            .GroupBy(NetworkMap.Endpoint).Select(g => g.First()).Take(25).ToList();
        var evidence = hits.Select(e => EventEvidence("network", e, new($"{e.ProcessName} → {NetworkMap.Endpoint(e)}", $"{e.ProcessName} ← {NetworkMap.Endpoint(e)}"), NetworkMap.Endpoint(e))).ToList();
        return Build(evidence, firstSeen: hits.FirstOrDefault()?.RelativeTime);
    }
}

public sealed class DroppedProcessNetworkRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-N002",
        Version = "1.0",
        Name = new("A newly created program went online", "برنامج أُنشئ حديثًا اتصل بالإنترنت"),
        Description = new("A program that was written to disk during the analysis then contacted an external address.", "برنامج كُتب على القرص أثناء التحليل اتصل لاحقًا بعنوان خارجي."),
        Category = FindingCategory.Network,
        Severity = Severity.High,
        Weight = 12,
        AttackTechniques = ["T1105"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var hits = context.TreeEvents.Where(e => e.Action == EventAction.NetworkConnect && NetworkMap.IsExternal(e)
            && context.NodeOf(e) is { ImageDroppedDuringAnalysis: true }).GroupBy(NetworkMap.Endpoint).Select(g => g.First()).ToList();
        var evidence = hits.Select(e => EventEvidence("network", e,
            new($"{e.ProcessName} (created during the analysis) connected to {NetworkMap.Endpoint(e)}", $"اتصل {e.ProcessName} (أُنشئ أثناء التحليل) بـ {NetworkMap.Endpoint(e)}"))).ToList();
        return Build(evidence, processes: hits.Select(context.NodeOf).Where(n => n is not null).Select(n => n!.Key), firstSeen: hits.FirstOrDefault()?.RelativeTime);
    }
}

public sealed class DnsActivityRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-N004",
        Version = "1.0",
        Name = new("Looked up domain names", "استعلم عن أسماء نطاقات"),
        Description = new("The program asked for the address of one or more domains. With networking disabled the lookups fail, but they show where the program tried to go.", "طلب البرنامج عنوان نطاق واحد أو أكثر. مع تعطيل الشبكة تفشل هذه الطلبات، لكنها تكشف الوجهات التي حاول البرنامج الوصول إليها."),
        Category = FindingCategory.Network,
        Severity = Severity.Informational,
        Weight = 2,
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var queries = context.TreeEvents.Where(e => e.Action == EventAction.DnsQuery)
            .GroupBy(e => e.Detail(DetailKeys.QueryName) ?? e.Target ?? "?", StringComparer.OrdinalIgnoreCase).Select(g => g.First()).Take(30).ToList();
        var evidence = queries.Select(e =>
        {
            var name = e.Detail(DetailKeys.QueryName) ?? e.Target ?? "?";
            return EventEvidence("dns", e, new($"{e.ProcessName} looked up {name}", $"استعلم {e.ProcessName} عن {name}"), name);
        }).ToList();
        return Build(evidence, firstSeen: queries.FirstOrDefault()?.RelativeTime);
    }
}

public sealed class UnsignedSampleRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-S001",
        Version = "1.0",
        Name = new("No valid digital signature", "لا يوجد توقيع رقمي صالح"),
        Description = new("The file is not signed, or its signature could not be validated. Many legitimate tools are unsigned; this only means the publisher cannot be confirmed.", "الملف غير موقّع أو تعذّر التحقق من توقيعه. كثير من الأدوات السليمة غير موقّعة، وهذا يعني فقط أنه لا يمكن تأكيد الناشر."),
        Category = FindingCategory.Static,
        Severity = Severity.Low,
        Weight = 5,
    };

    public override Finding? Evaluate(RuleContext context)
    {
        if (context.Static?.Pe is null) return null;
        var sig = context.Static.Signature;
        if (sig.Status is SignatureStatus.Valid or SignatureStatus.PresentUnverified) return null;
        var invalid = sig.Status == SignatureStatus.Invalid;
        return Build(
            [new Evidence
            {
                Kind = "static",
                Description = invalid ? new("The signature is present but invalid", "التوقيع موجود لكنه غير صالح") : new("The file has no Authenticode signature", "الملف لا يحتوي على توقيع Authenticode"),
                Technical = sig.Detail ?? sig.Publisher,
            }],
            severity: invalid ? Severity.High : Severity.Low);
    }
}

public sealed class PackedSampleRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-S002",
        Version = "1.0",
        Name = new("Compressed or encrypted code sections", "أقسام برمجية مضغوطة أو مشفّرة"),
        Description = new("Parts of the program look compressed or encrypted (very high entropy). Packers are used by legitimate software to save space and by malware to hide code.", "بعض أجزاء البرنامج تبدو مضغوطة أو مشفّرة (Entropy مرتفع جدًا). تستخدم البرامج السليمة الضغط لتقليل الحجم، وتستخدمه البرمجيات الخبيثة لإخفاء الكود."),
        Category = FindingCategory.Static,
        Severity = Severity.Low,
        Weight = 6,
        AttackTechniques = ["T1027.002"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var sections = context.Static?.Pe?.Sections.Where(s => s.Executable && s.Entropy >= Entropy.PackedThreshold && s.RawSize > 1024).ToList() ?? [];
        var evidence = sections.Select(s => new Evidence
        {
            Kind = "static",
            Description = new($"Section {s.Name} has entropy {s.Entropy:0.00}", $"القسم {s.Name} لديه Entropy بقيمة {s.Entropy:0.00}"),
            Technical = $"{s.Name}: entropy {s.Entropy:0.000}, raw {s.RawSize} bytes",
        }).ToList();
        return Build(evidence);
    }
}

public sealed class InjectionCapabilityRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-S003",
        Version = "1.0",
        Name = new("Can modify other running programs", "قادر على تعديل برامج أخرى قيد التشغيل"),
        Description = new("The file imports the set of Windows functions used to write into and start code inside other processes. Debuggers and security tools use them too; this is a capability, not an observed action.", "يستورد الملف مجموعة دوال Windows المستخدمة للكتابة داخل عمليات أخرى وتشغيل أكواد فيها. أدوات التصحيح والحماية تستخدمها أيضًا؛ هذه قدرة وليست سلوكًا تمت ملاحظته."),
        Category = FindingCategory.Static,
        Severity = Severity.Medium,
        Weight = 8,
        AttackTechniques = ["T1055"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var functions = context.Static?.Pe?.Imports.SelectMany(i => i.Functions).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (functions is null) return null;
        var write = functions.Contains("WriteProcessMemory");
        var alloc = functions.Contains("VirtualAllocEx") || functions.Contains("NtAllocateVirtualMemory");
        var start = functions.Contains("CreateRemoteThread") || functions.Contains("NtCreateThreadEx") || functions.Contains("QueueUserAPC") || functions.Contains("SetThreadContext");
        if (!(write && alloc && start)) return null;
        var found = new[] { "VirtualAllocEx", "NtAllocateVirtualMemory", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext" }
            .Where(functions.Contains);
        return Build([new Evidence
        {
            Kind = "static",
            Description = new("Imports remote memory and thread functions", "يستورد دوال الذاكرة والخيوط عن بُعد"),
            Technical = string.Join(", ", found),
        }]);
    }
}

public sealed class MonitoringInterruptedRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-M001",
        Version = "1.0",
        Name = new("Monitoring was interrupted", "توقفت المراقبة قبل انتهاء التحليل"),
        Description = new("The monitoring agent stopped reporting before the analysis finished. The results may be incomplete. Some programs deliberately stop monitoring tools.", "توقف وكيل المراقبة عن الإرسال قبل انتهاء التحليل، لذا قد تكون النتائج ناقصة. بعض البرامج توقف أدوات المراقبة عمدًا."),
        Category = FindingCategory.Monitoring,
        Severity = Severity.Medium,
        Weight = 10,
        AttackTechniques = ["T1562"],
    };

    public override Finding? Evaluate(RuleContext context)
    {
        if (!context.MonitoringInterrupted) return null;
        var marker = context.Events.LastOrDefault(e => e.Action == EventAction.MonitoringInterrupted);
        return Build([new Evidence
        {
            Kind = "monitoring",
            Description = new("No heartbeat was received from the agent", "لم يصل أي إشارة نبض من الوكيل"),
            Technical = marker?.Detail(DetailKeys.Reason),
            EventSequences = marker is null ? [] : [marker.Sequence],
        }]);
    }
}

/// <summary>Contextual scoring: the full drop → run → persist → connect sequence counts more than its parts.</summary>
public sealed class FullChainRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-C001",
        Version = "1.0",
        Name = new("Dropped, ran, persisted and connected", "أنشأ ملفًا وشغّله وثبّته واتصل بالخارج"),
        Description = new("One chain of related actions: a new program was written, started, configured to run again later, and contacted the internet. Each step alone can be normal; together they form a pattern typical of unwanted software installing itself.", "سلسلة واحدة من الأفعال المترابطة: كُتب برنامج جديد، ثم شُغّل، ثم ضُبط ليعمل لاحقًا، ثم اتصل بالإنترنت. كل خطوة منفردة قد تكون طبيعية، لكنها مجتمعة تشكّل نمطًا معتادًا للبرامج غير المرغوبة عند تثبيت نفسها."),
        Category = FindingCategory.Sequence,
        Severity = Severity.Critical,
        Weight = 15,
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var chains = CorrelationEngine.BuildChains(context.Events, context.Graph, context.Persistence, context.Network)
            .Where(c => c.Steps.Any(s => s.Kind == ChainStepKind.Dropped) && c.Steps.Any(s => s.Kind == ChainStepKind.Persisted) && c.Steps.Any(s => s.Kind == ChainStepKind.Connected))
            .ToList();
        var evidence = chains.Select(c => new Evidence
        {
            Kind = "chain",
            Description = new(string.Join(" → ", c.Steps.Select(s => $"{s.Kind}: {s.Target}")), string.Join(" ← ", c.Steps.Select(s => s.Target))),
            EventSequences = c.Steps.Select(s => s.EventSequence).Distinct().ToList(),
        }).ToList();
        return Build(evidence);
    }
}

public sealed class WatchlistRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-W001",
        Version = "1.0",
        Name = new("Matched your watchlist", "تطابق مع قائمة المراقبة الخاصة بك"),
        Description = new("Something in this analysis matches an entry you added to your local watchlist.", "شيء في هذا التحليل يطابق إدخالًا أضفته إلى قائمة المراقبة المحلية."),
        Category = FindingCategory.Watchlist,
        Severity = Severity.High,
        Weight = 20,
    };

    public override Finding? Evaluate(RuleContext context)
    {
        if (context.Watchlist.Count == 0) return null;
        var evidence = new List<Evidence>();
        foreach (var entry in context.Watchlist)
        {
            switch (entry.Type)
            {
                case WatchlistEntryType.Sha256 when context.Sample.Sha256.Equals(entry.Value, StringComparison.OrdinalIgnoreCase):
                    evidence.Add(Match(entry, "sample", null));
                    break;
                case WatchlistEntryType.Sha256:
                    AddEvents(e => string.Equals(e.Detail(DetailKeys.Sha256), entry.Value, StringComparison.OrdinalIgnoreCase));
                    break;
                case WatchlistEntryType.Domain:
                    AddEvents(e => e.Action == EventAction.DnsQuery && Glob.IsMatch(e.Detail(DetailKeys.QueryName) ?? e.Target, entry.Value));
                    break;
                case WatchlistEntryType.IpAddress:
                    AddEvents(e => e.Category == EventCategory.Network && string.Equals(e.Detail(DetailKeys.RemoteAddress) ?? e.Target, entry.Value, StringComparison.OrdinalIgnoreCase));
                    break;
                case WatchlistEntryType.FilePath:
                    AddEvents(e => e.Category == EventCategory.File && Glob.IsMatch(e.Target, entry.Value));
                    break;
                case WatchlistEntryType.ProcessName:
                    AddEvents(e => e.Action == EventAction.ProcessStart && Glob.IsMatch(e.ProcessName, entry.Value));
                    break;
            }

            void AddEvents(Func<AnalysisEvent, bool> predicate)
            {
                var hits = context.Events.Where(predicate).Take(10).ToList();
                if (hits.Count > 0) evidence.Add(Match(entry, hits[0].Target ?? hits[0].ProcessName, hits.Select(h => h.Sequence).ToList()));
            }
        }
        return Build(evidence);
    }

    private static Evidence Match(WatchlistEntry entry, string? seen, IReadOnlyList<long>? sequences) => new()
    {
        Kind = "watchlist",
        Description = new($"Watchlist {entry.Type}: {entry.Value}" + (entry.Note is null ? string.Empty : $" ({entry.Note})"), $"قائمة المراقبة ({entry.Type}): {entry.Value}"),
        Technical = seen,
        EventSequences = sequences ?? [],
    };
}
