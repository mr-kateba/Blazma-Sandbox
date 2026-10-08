using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Blazma.Contracts;

namespace Blazma.Agent.Collect;

/// <summary>A file written by a process of the analyzed tree.</summary>
internal sealed record DropCandidate(string Path, int ProcessId, string ProcessName);

/// <summary>
/// Copies files the analyzed programs wrote out of the sandbox at the end of the run, so
/// the host can analyze them statically and with YARA. Executables and scripts first;
/// bounded in count and size; the sample itself and system noise are skipped.
/// </summary>
internal sealed class DroppedFileCollector(EventSink sink, int maxFiles, long maxFileBytes)
{
    private readonly ConcurrentDictionary<string, DropCandidate> _candidates = new(StringComparer.OrdinalIgnoreCase);

    private static readonly string[] ExecutableExtensions =
        [".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx", ".msi", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk", ".jar"];

    private static readonly string[] NoisyFragments =
        [@"\windows\prefetch\", @"\windows\logs\", @"\$recycle.bin\", @"\appdata\local\microsoft\windows\inetcache\", @"\windows\servicing\",
         @"\windows\softwaredistribution\", @"\programdata\microsoft\windows defender\", @"\appdata\local\microsoft\edge\user data\"];

    public void Observe(string path, int pid, string processName)
    {
        if (_candidates.Count >= 5000 || string.IsNullOrEmpty(path)) return;
        _candidates.TryAdd(path, new DropCandidate(path, pid, processName));
    }

    /// <summary>Orders candidates: PE files, then scripts and shortcuts, then the rest. Pure, for tests.</summary>
    public static IReadOnlyList<DropCandidate> Prioritize(IEnumerable<DropCandidate> candidates, Func<string, (long Size, bool IsPe)?> facts, long maxFileBytes, IReadOnlyCollection<string> excludedPrefixes)
    {
        var ranked = new List<(DropCandidate C, int Rank)>();
        foreach (var c in candidates)
        {
            var lower = c.Path.ToLowerInvariant();
            if (excludedPrefixes.Any(p => lower.StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;
            if (NoisyFragments.Any(f => lower.Contains(f, StringComparison.Ordinal))) continue;
            if (lower.EndsWith(".pf", StringComparison.Ordinal) || lower.EndsWith(".etl", StringComparison.Ordinal) || lower.EndsWith(".tmp", StringComparison.Ordinal) && !lower.Contains(@"\temp\", StringComparison.Ordinal)) continue;
            if (facts(c.Path) is not { } f || f.Size <= 0 || f.Size > maxFileBytes) continue;
            var ext = Path.GetExtension(lower);
            var rank = f.IsPe ? 3 : ExecutableExtensions.Contains(ext) ? 2 : f.Size <= 1024 * 1024 ? 1 : 0;
            if (rank == 0) continue;
            ranked.Add((c, rank));
        }
        return ranked.OrderByDescending(r => r.Rank).ThenBy(r => r.C.Path, StringComparer.OrdinalIgnoreCase).Select(r => r.C).ToList();
    }

    /// <summary>Copies the best candidates out. Returns how many were written.</summary>
    public int Collect(string sampleSha256, IReadOnlyCollection<string> excludedPrefixes)
    {
        var ordered = Prioritize(_candidates.Values, Facts, maxFileBytes, excludedPrefixes);
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { sampleSha256 };
        var index = 0;
        foreach (var c in ordered)
        {
            if (index >= maxFiles) break;
            byte[] data;
            try
            {
                using var s = new FileStream(c.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (s.Length > maxFileBytes) continue;
                data = new byte[s.Length];
                s.ReadExactly(data);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or EndOfStreamException)
            {
                continue;
            }
            var sha = Convert.ToHexStringLower(SHA256.HashData(data));
            if (!hashes.Add(sha)) continue;
            index++;
            sink.WriteSigned(Protocol.DroppedDataName(index), data);
            sink.WriteSigned(Protocol.DroppedMetaName(index), JsonSerializer.SerializeToUtf8Bytes(new DroppedFileDto
            {
                OriginalPath = c.Path,
                ProcessName = c.ProcessName,
                ProcessId = c.ProcessId,
                Size = data.Length,
                Sha256 = sha,
            }, ProtocolJson.Default.DroppedFileDto));
        }
        return index;
    }

    private static (long Size, bool IsPe)? Facts(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Attributes.HasFlag(FileAttributes.ReparsePoint)) return null;
            Span<byte> head = stackalloc byte[2];
            using var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var isPe = s.Read(head) == 2 && head[0] == (byte)'M' && head[1] == (byte)'Z';
            return (info.Length, isPe);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
