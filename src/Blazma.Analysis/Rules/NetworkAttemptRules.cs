using System.Globalization;
using Blazma.Analysis.Engine;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Findings;
using Blazma.Core.Text;

namespace Blazma.Analysis.Rules;

/// <summary>
/// Destinations count as evidence whether or not they answered: with networking off or
/// simulated, a hard-coded server never answers, and the attempt is all there is to see.
/// </summary>
internal static class Destinations
{
    public static IReadOnlyList<NetworkDestination> Of(RuleContext context) => NetworkDestinations.Build(context.Events, context.Graph, context.Network);

    public static LocalizedText Outcome(NetworkDestination d) => d.Status switch
    {
        DestinationStatus.Connected => new("connected", "اتصل فعلًا"),
        DestinationStatus.Simulated => new("answered by the simulated internet", "أجاب عنه الإنترنت الوهمي"),
        DestinationStatus.Failed => NetworkDestinations.DescribeError(d.ErrorCode),
        _ => new("no answer seen", "لم يُرصد رد"),
    };

    public static string Attempts(NetworkDestination d, bool arabic) =>
        d.Count == 1 ? arabic ? "محاولة واحدة" : "1 attempt" : arabic ? $"{d.Count.ToString(CultureInfo.InvariantCulture)} محاولات" : $"{d.Count.ToString(CultureInfo.InvariantCulture)} attempts";
}

/// <summary>An external IP address used straight away, with no name lookup leading to it: the classic hard-coded server.</summary>
public sealed class DirectIpContactRule : Rule
{
    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-N007",
        Version = "1.0",
        Name = new("Tried to reach an internet address directly, without a name lookup", "حاول الوصول إلى عنوان على الإنترنت مباشرةً دون استعلام عن اسم"),
        Description = new(
            "Programs normally find their servers by name (DNS) and connect to the address the lookup returns. Here a program went straight to a fixed IP address that no lookup in this analysis returned. Malware often does this to reach a hard-coded command-and-control server, and it counts whether or not the address answered. Some legitimate software (peer-to-peer, some updaters and telemetry) does it too, so read it together with the other findings.",
            "تعثر البرامج عادةً على خوادمها بالاسم (DNS) ثم تتصل بالعنوان الذي يعيده الاستعلام. أما هنا فقد توجّه برنامج مباشرةً إلى عنوان IP ثابت لم يُعِده أي استعلام في هذا التحليل. تفعل البرمجيات الخبيثة ذلك كثيرًا للوصول إلى خادم تحكّم مكتوب في شيفرتها، ويُحتسب هذا سواء أجاب العنوان أم لم يُجب. وتفعله أيضًا بعض البرامج السليمة (كتطبيقات النظير للنظير وبعض أدوات التحديث والقياس)، فاقرأه مع بقية النتائج."),
        Category = FindingCategory.Network,
        Severity = Severity.Medium,
        Weight = 8,
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var hits = Destinations.Of(context).Where(d => d.DirectIp).Take(25).ToList();
        var evidence = hits.Select(d =>
        {
            var who = string.Join(", ", d.Processes);
            var outcome = Destinations.Outcome(d);
            return new Evidence
            {
                Kind = "network",
                Description = new($"{who} tried to reach {d.Endpoint} ({d.Protocol}) directly · {Destinations.Attempts(d, false)} · {outcome.En}",
                    $"حاول {who} الوصول إلى {d.Endpoint} ({d.Protocol}) مباشرةً · {Destinations.Attempts(d, true)} · {outcome.Ar}"),
                Technical = d.Endpoint,
                EventSequences = d.EventSequences,
            };
        }).ToList();
        var processes = hits.SelectMany(d => d.EventSequences.Take(1))
            .Select(seq => context.Events.FirstOrDefault(e => e.Sequence == seq)).OfType<AnalysisEvent>()
            .Select(context.NodeOf).OfType<Core.Processes.ProcessNode>().Select(n => n.Key);
        return Build(evidence, processes: processes, firstSeen: hits.Count == 0 ? null : hits.Min(d => d.FirstSeen));
    }
}

/// <summary>The same unreachable server tried again and again: the retry loop of a program waiting for its server.</summary>
public sealed class RepeatedUnansweredContactRule : Rule
{
    public const int MinAttempts = 3;

    public override RuleMetadata Metadata { get; } = new()
    {
        Id = "BLZ-N008",
        Version = "1.0",
        Name = new("Kept retrying a server that did not answer", "كرّر محاولة الوصول إلى خادم لم يُجب"),
        Description = new(
            "A program tried the same external address and port several times without a connection being made. Malware waiting for its server retries like this (beaconing). In an analysis without a real network every attempt fails, so the number of attempts shows how persistent the program is, not that the server exists.",
            "حاول برنامج الوصول إلى العنوان الخارجي والمنفذ نفسيهما عدة مرات دون أن يتم الاتصال. تكرّر البرمجيات الخبيثة المحاولة بهذا الشكل وهي تنتظر خادمها (Beaconing). في تحليل بلا شبكة حقيقية تفشل كل المحاولات، لذا يدل عددها على إصرار البرنامج لا على وجود الخادم."),
        Category = FindingCategory.Network,
        Severity = Severity.Low,
        Weight = 4,
    };

    public override Finding? Evaluate(RuleContext context)
    {
        var hits = Destinations.Of(context)
            .Where(d => d.External && d.Address is not null && d.Status is DestinationStatus.Failed or DestinationStatus.Attempted && d.Count >= MinAttempts)
            .OrderByDescending(d => d.Count).Take(25).ToList();
        var evidence = hits.Select(d => new Evidence
        {
            Kind = "network",
            Description = new($"{string.Join(", ", d.Processes)} → {d.Endpoint} · {Destinations.Attempts(d, false)} · {Destinations.Outcome(d).En}",
                $"{string.Join("، ", d.Processes)} ← {d.Endpoint} · {Destinations.Attempts(d, true)} · {Destinations.Outcome(d).Ar}"),
            Technical = d.Domain is null ? d.Endpoint : $"{d.Domain} → {d.Endpoint}",
            EventSequences = d.EventSequences,
        }).ToList();
        return Build(evidence, firstSeen: hits.Count == 0 ? null : hits.Min(d => d.FirstSeen));
    }
}
