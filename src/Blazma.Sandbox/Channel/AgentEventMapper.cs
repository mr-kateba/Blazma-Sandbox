using System.Text.RegularExpressions;
using Blazma.Contracts;
using Blazma.Core.Events;

namespace Blazma.Sandbox.Channel;

/// <summary>
/// Converts agent DTOs into domain events. Everything is treated as hostile input:
/// unknown actions are dropped, strings are clipped, detail counts are capped, and paths
/// are normalised before anything downstream sees them.
/// </summary>
public static partial class AgentEventMapper
{
    public static AnalysisEvent? Map(AgentEventDto dto, DateTimeOffset sampleStart, long hostSequence)
    {
        if (!Enum.TryParse<EventAction>(dto.Action, ignoreCase: true, out var action) || !Enum.IsDefined(action)) return null;
        if (dto.ProcessId < 0 || dto.ParentProcessId < 0) return null;

        var category = action.DefaultCategory();
        var details = new Dictionary<string, string>(StringComparer.Ordinal);
        if (dto.Details is not null)
        {
            foreach (var (k, v) in dto.Details.Take(Protocol.Limits.MaxDetails))
            {
                if (string.IsNullOrEmpty(k) || k.Length > 64 || v is null) continue;
                details[Clip(k)] = Clip(v);
            }
        }

        var target = dto.Target is null ? null : Clip(dto.Target);
        if (target is not null)
        {
            target = category switch
            {
                EventCategory.File => NormalizeFile(target),
                EventCategory.Registry => NormalizeRegistry(target),
                _ => target,
            };
        }
        if (details.TryGetValue(DetailKeys.NewPath, out var np)) details[DetailKeys.NewPath] = NormalizeFile(np);
        if (details.TryGetValue(DetailKeys.ImagePath, out var ip)) details[DetailKeys.ImagePath] = NormalizeFile(ip);

        var rel = TimeSpan.FromMilliseconds(Math.Clamp(dto.RelativeMs, -86_400_000L, 86_400_000L));
        return new AnalysisEvent
        {
            Sequence = hostSequence,
            Timestamp = sampleStart + rel,
            RelativeTime = rel,
            Category = category,
            Action = action,
            ProcessId = dto.ProcessId,
            ParentProcessId = dto.ParentProcessId,
            Process = dto.ProcessStartMs != 0 || action == EventAction.ProcessStart
                ? new ProcessKey(dto.ProcessId, TimeSpan.FromMilliseconds(dto.ProcessStartMs).Ticks)
                : null,
            ProcessName = SafeName(dto.ProcessName),
            Target = target,
            Details = details,
            Source = Clip(dto.Source.Length > 64 ? dto.Source[..64] : dto.Source),
        };
    }

    private static string Clip(string s)
    {
        if (s.Length > Protocol.Limits.MaxStringLength) s = s[..Protocol.Limits.MaxStringLength];
        // Control characters (other than tab) have no business in paths or names and can confuse terminals and logs.
        return ControlChars().Replace(s, "�");
    }

    private static string SafeName(string name)
    {
        name = Clip(name);
        return name.Length > 260 ? name[..260] : name;
    }

    private static string NormalizeFile(string path)
    {
        if (path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path[4..];
        var m = DeviceVolume().Match(path);
        return m.Success ? "C:" + path[m.Length..] : path;
    }

    private static string NormalizeRegistry(string key)
    {
        if (key.StartsWith(@"\REGISTRY\MACHINE", StringComparison.OrdinalIgnoreCase)) return "HKLM" + key[17..];
        var m = UserSid().Match(key);
        if (m.Success) return (m.Groups["c"].Success ? @"HKCU\Software\Classes" : "HKCU") + key[m.Length..];
        return key;
    }

    [GeneratedRegex(@"[\x00-\x08\x0B-\x1F\x7F]")]
    private static partial Regex ControlChars();

    [GeneratedRegex(@"^\\Device\\HarddiskVolume\d+", RegexOptions.IgnoreCase)]
    private static partial Regex DeviceVolume();

    [GeneratedRegex(@"^\\REGISTRY\\USER\\S-1-5-21-[\d-]+(?<c>_Classes)?", RegexOptions.IgnoreCase)]
    private static partial Regex UserSid();
}
