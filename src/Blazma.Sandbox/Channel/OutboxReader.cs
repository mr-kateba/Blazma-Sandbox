using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Blazma.Contracts;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Snapshots;
using Blazma.Sandbox.Imaging;

namespace Blazma.Sandbox.Channel;

/// <summary>
/// Reads the sandbox's writable <c>out/</c> folder. This is the one place where data
/// produced inside the sandbox enters the host, so it is deliberately strict:
/// <list type="bullet">
/// <item>only the exact file names in <see cref="Protocol.IsAllowedOutboxName"/> are opened (the plain-text
/// diagnostic logs are read separately by <see cref="AgentDiagnostics"/>);</item>
/// <item>reparse points (symlinks, junctions) are never followed;</item>
/// <item>per-file and per-analysis byte quotas are enforced;</item>
/// <item>every signed file must carry a valid MAC;</item>
/// <item>nothing from the folder is ever executed or opened by another program.</item>
/// </list>
/// </summary>
public sealed class OutboxReader(string outFolder, byte[] channelKey, long quotaBytes)
{
    private int _nextChunk = 1;
    private int _nextScreenshot = 1;
    private int _nextDropped = 1;
    private int _nextMemory = 1;
    private long _hostSequence;
    private long _bytesRead;
    private readonly HashSet<string> _reported = new(StringComparer.OrdinalIgnoreCase);

    public long BytesRead => _bytesRead;
    public bool QuotaExceeded { get; private set; }
    public int RejectedFiles { get; private set; }
    public int TamperedFiles { get; private set; }
    public int MalformedLines { get; private set; }
    public List<string> Problems { get; } = [];

    public bool HasHello => File.Exists(Path.Combine(outFolder, Protocol.HelloFile));
    public bool HasDone => File.Exists(Path.Combine(outFolder, Protocol.DoneFile));

    public HelloDto? ReadHello() => ReadJson(Protocol.HelloFile, ProtocolJson.Default.HelloDto, signed: false);
    public HeartbeatDto? ReadHeartbeat() => ReadJson(Protocol.HeartbeatFile, ProtocolJson.Default.HeartbeatDto, signed: true);
    public DoneDto? ReadDone() => ReadJson(Protocol.DoneFile, ProtocolJson.Default.DoneDto, signed: true);

    public SystemSnapshot? ReadSnapshot(bool after)
    {
        var dto = ReadJson(after ? Protocol.AfterFile : Protocol.BaselineFile, ProtocolJson.Default.SnapshotDto, signed: true);
        if (dto is null) return null;
        var cap = Protocol.Limits.MaxSnapshotEntries;
        return new SystemSnapshot
        {
            TakenAt = dto.TakenAt,
            Files = dto.Files.Take(cap).Select(f => new FileEntry(f.Path, f.Size, f.LastWriteUtc, f.Sha256)).ToList(),
            Registry = dto.Registry.Take(cap).Select(r => new RegistryEntry(r.Key, r.ValueName, r.Data)).ToList(),
            Services = dto.Services.Take(cap).ToList(),
            ScheduledTasks = dto.ScheduledTasks.Take(cap).ToList(),
            StartupItems = dto.StartupItems.Take(cap).ToList(),
        };
    }

    /// <summary>Reads every complete event chunk not read yet, in order. Stops at the first gap.</summary>
    public IReadOnlyList<AnalysisEvent> ReadNewEvents(DateTimeOffset sampleStart)
    {
        ReportUnexpectedFiles();
        var events = new List<AnalysisEvent>();
        while (!QuotaExceeded && _nextChunk <= Protocol.Limits.MaxChunkFiles)
        {
            var name = Protocol.EventChunkName(_nextChunk);
            var bytes = ReadBytes(name);
            if (bytes is null) break;
            _nextChunk++;

            var content = SignedFile.Verify(bytes, channelKey);
            if (content is null)
            {
                TamperedFiles++;
                Problems.Add($"{name}: signature check failed; the chunk was discarded.");
                continue;
            }

            foreach (var line in SplitLines(content))
            {
                if (line.Length == 0) continue;
                if (line.Length > Protocol.Limits.MaxLineBytes) { MalformedLines++; continue; }
                AgentEventDto? dto;
                try { dto = JsonSerializer.Deserialize(line, ProtocolJson.Default.AgentEventDto); }
                catch (JsonException) { MalformedLines++; continue; }
                if (dto is null) { MalformedLines++; continue; }
                var e = AgentEventMapper.Map(dto, sampleStart, ++_hostSequence);
                if (e is null) { MalformedLines++; continue; }
                events.Add(e);
            }
        }
        return events;
    }

    /// <summary>
    /// Reads new screenshots in order and stores them as PNG under <paramref name="artifactsFolder"/>.
    /// Pixels are inflated into a buffer of exactly the announced size and re-encoded by the host.
    /// </summary>
    public IReadOnlyList<CollectedScreenshot> ReadNewScreenshots(string artifactsFolder)
    {
        var result = new List<CollectedScreenshot>();
        while (!QuotaExceeded && _nextScreenshot <= Protocol.Limits.MaxScreenshots)
        {
            var name = Protocol.ScreenshotName(_nextScreenshot);
            var bytes = ReadBytes(name);
            if (bytes is null) break;
            var index = _nextScreenshot++;
            var content = VerifyOrReport(name, bytes);
            if (content is null) continue;
            if (!RawFrame.TryDecode(content, Protocol.Limits.MaxScreenshotWidth, Protocol.Limits.MaxScreenshotHeight, out var w, out var h, out var ms, out var pixels))
            {
                RejectedFiles++;
                Problems.Add($"{name}: not a valid screenshot; ignored.");
                continue;
            }
            var folder = Directory.CreateDirectory(Path.Combine(artifactsFolder, "screenshots")).FullName;
            var path = Path.Combine(folder, $"{index:D4}.png");
            var png = PngEncoder.EncodeBgra(w, h, pixels);
            SharedFileRetry.Default.Run(() => File.WriteAllBytes(path, png));
            result.Add(new CollectedScreenshot(TimeSpan.FromMilliseconds(ms), path, w, h));
        }
        return result;
    }

    /// <summary>
    /// Reads files the agent copied out. Each must match its signed sidecar (size and SHA-256).
    /// Copies are stored as <c>dropped/NNNN.bin</c>: no original name or extension on disk, so
    /// nothing can be started by double-clicking it.
    /// </summary>
    public IReadOnlyList<CollectedDroppedFile> ReadDroppedFiles(string artifactsFolder, int maxFiles)
    {
        var result = new List<CollectedDroppedFile>();
        var cap = Math.Min(maxFiles, Protocol.Limits.MaxDroppedFiles);
        while (!QuotaExceeded && _nextDropped <= cap)
        {
            var index = _nextDropped;
            var meta = ReadJson(Protocol.DroppedMetaName(index), ProtocolJson.Default.DroppedFileDto, signed: true);
            if (meta is null) break;
            _nextDropped++;
            var dataName = Protocol.DroppedDataName(index);
            var data = ReadBytes(dataName) is { } raw ? VerifyOrReport(dataName, raw) : null;
            if (data is null || !MatchesHash(data, meta.Size, meta.Sha256))
            {
                RejectedFiles++;
                Problems.Add($"{dataName}: missing or does not match its description; ignored.");
                continue;
            }
            var folder = Directory.CreateDirectory(Path.Combine(artifactsFolder, "dropped")).FullName;
            var path = Path.Combine(folder, $"{index:D4}.bin");
            SharedFileRetry.Default.Run(() => File.WriteAllBytes(path, data));
            result.Add(new CollectedDroppedFile(CleanText(meta.OriginalPath, 1024), CleanText(meta.ProcessName, 260), path, meta.Sha256.ToLowerInvariant(), data.Length));
        }
        return result;
    }

    /// <summary>Reads dumped memory regions, validated against their signed sidecars.</summary>
    public IReadOnlyList<CollectedMemoryRegion> ReadMemoryRegions(string artifactsFolder, int maxRegions)
    {
        var result = new List<CollectedMemoryRegion>();
        var cap = Math.Min(maxRegions, Protocol.Limits.MaxMemoryRegions);
        while (!QuotaExceeded && _nextMemory <= cap)
        {
            var index = _nextMemory;
            var meta = ReadJson(Protocol.MemoryMetaName(index), ProtocolJson.Default.MemoryRegionDto, signed: true);
            if (meta is null) break;
            _nextMemory++;
            var kind = meta.Kind switch
            {
                "private-exec" => MemoryRegionKind.PrivateExecutable,
                "rwx" => MemoryRegionKind.ReadWriteExecute,
                "unbacked-image" => MemoryRegionKind.UnbackedImage,
                _ => (MemoryRegionKind?)null,
            };
            var dataName = Protocol.MemoryDataName(index);
            var data = ReadBytes(dataName) is { } raw ? VerifyOrReport(dataName, raw) : null;
            if (kind is null || meta.ProcessId < 0 || data is null || data.Length > Protocol.Limits.MaxMemoryRegionBytes || !MatchesHash(data, meta.Size, meta.Sha256))
            {
                RejectedFiles++;
                Problems.Add($"{dataName}: missing, oversized or inconsistent; ignored.");
                continue;
            }
            var folder = Directory.CreateDirectory(Path.Combine(artifactsFolder, "memory")).FullName;
            var path = Path.Combine(folder, $"{index:D4}.bin");
            SharedFileRetry.Default.Run(() => File.WriteAllBytes(path, data));
            result.Add(new CollectedMemoryRegion(meta.ProcessId, CleanText(meta.ProcessName, 260), meta.BaseAddress, data.Length,
                CleanText(meta.Protection, 64), kind.Value, path, meta.Sha256.ToLowerInvariant()));
        }
        return result;
    }

    /// <summary>Reads the network capture, if any. Only a pcapng file (by its magic number) is accepted.</summary>
    public string? ReadPcap(string artifactsFolder)
    {
        var bytes = ReadBytes(Protocol.PcapFile);
        if (bytes is null) return null;
        var content = VerifyOrReport(Protocol.PcapFile, bytes);
        if (content is null) return null;
        if (content.Length < 12 || content.Length > Protocol.Limits.MaxPcapBytes || !content.AsSpan(0, 4).SequenceEqual(PcapNgMagic))
        {
            RejectedFiles++;
            Problems.Add($"{Protocol.PcapFile}: not a pcapng capture; ignored.");
            return null;
        }
        Directory.CreateDirectory(artifactsFolder);
        var path = Path.Combine(artifactsFolder, "capture.pcapng");
        SharedFileRetry.Default.Run(() => File.WriteAllBytes(path, content));
        return path;
    }

    private static ReadOnlySpan<byte> PcapNgMagic => [0x0A, 0x0D, 0x0D, 0x0A];

    private byte[]? VerifyOrReport(string name, byte[] bytes)
    {
        var content = SignedFile.Verify(bytes, channelKey);
        if (content is not null) return content;
        TamperedFiles++;
        Problems.Add($"{name}: signature check failed; discarded.");
        return null;
    }

    private static bool MatchesHash(byte[] data, long size, string sha256) =>
        data.LongLength == size && sha256.Length == 64
        && Convert.ToHexStringLower(SHA256.HashData(data)).Equals(sha256, StringComparison.OrdinalIgnoreCase);

    private static string CleanText(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "?";
        if (s.Length > max) s = s[..max];
        return new string(s.Select(c => char.IsControl(c) && c != '\t' ? '\uFFFD' : c).ToArray());
    }

    private static IEnumerable<byte[]> SplitLines(byte[] content)
    {
        var start = 0;
        for (var i = 0; i <= content.Length; i++)
        {
            if (i < content.Length && content[i] != (byte)'\n') continue;
            var len = i - start;
            if (len > 0 && content[start + len - 1] == (byte)'\r') len--;
            yield return content.AsSpan(start, Math.Max(0, len)).ToArray();
            start = i + 1;
        }
    }

    private T? ReadJson<T>(string name, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type, bool signed) where T : class
    {
        var bytes = ReadBytes(name);
        if (bytes is null) return null;
        var content = signed ? SignedFile.Verify(bytes, channelKey) : bytes;
        if (content is null)
        {
            TamperedFiles++;
            Problems.Add($"{name}: signature check failed.");
            return null;
        }
        try { return JsonSerializer.Deserialize(content, type); }
        catch (JsonException) { Problems.Add($"{name}: malformed JSON."); return null; }
    }

    private byte[]? ReadBytes(string name)
    {
        if (!Protocol.IsAllowedOutboxName(name)) return null;
        var path = Path.Combine(outFolder, name);
        FileInfo info;
        try
        {
            info = new FileInfo(path);
            if (!info.Exists) return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }

        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint) || info.LinkTarget is not null)
        {
            RejectedFiles++;
            Problems.Add($"{name}: is a link; ignored.");
            return null;
        }
        if (info.Length > Protocol.Limits.MaxFileBytes)
        {
            RejectedFiles++;
            Problems.Add($"{name}: larger than {Protocol.Limits.MaxFileBytes} bytes; ignored.");
            return null;
        }
        if (_bytesRead + info.Length > quotaBytes)
        {
            QuotaExceeded = true;
            Problems.Add("The sandbox wrote more data than the configured quota; reading stopped.");
            return null;
        }

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);
            var buffer = new byte[Math.Min(stream.Length, Protocol.Limits.MaxFileBytes)];
            stream.ReadExactly(buffer);
            _bytesRead += buffer.Length;
            return buffer;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or EndOfStreamException)
        {
            return null;
        }
    }

    private void ReportUnexpectedFiles()
    {
        try
        {
            foreach (var file in Directory.EnumerateFiles(outFolder).Take(10_000))
            {
                var name = Path.GetFileName(file);
                if (Protocol.IsAllowedOutboxName(name) || AgentDiagnostics.IsDiagnosticName(name) || name.EndsWith(Protocol.TempExtension, StringComparison.Ordinal)) continue;
                if (_reported.Add(name))
                {
                    RejectedFiles++;
                    Problems.Add($"Unexpected file in the output folder was ignored: {Truncate(name)}");
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static string Truncate(string s) => s.Length > 80 ? s[..80] + "…" : s;
}
