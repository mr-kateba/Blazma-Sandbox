using System.Text.Json;
using Blazma.Contracts;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;

namespace Blazma.Sandbox.Channel;

/// <summary>Limits the agent applies to what it copies out of the sandbox. The host enforces its own limits again.</summary>
public sealed record AgentLimits(int MaxDroppedFiles, long MaxDroppedFileBytes, long MaxMemoryBytes, int MaxScreenshots)
{
    public static AgentLimits Default { get; } = new(25, 32L * 1024 * 1024, 128L * 1024 * 1024, 120);
}

/// <summary>Helpers shared by every provider that talks to the agent through files.</summary>
public static class ChannelFiles
{
    /// <summary>The agent configuration for one run. Every provider builds it here so they cannot drift apart.</summary>
    public static SessionConfigDto CreateConfig(SandboxSessionRequest request, byte[] channelKey, bool stopWhenTreeExits, AgentLimits? limits = null)
    {
        var o = request.Options;
        limits ??= AgentLimits.Default;
        return new SessionConfigDto
        {
            AnalysisId = request.AnalysisId,
            DurationSeconds = (int)o.Duration.TotalSeconds,
            CaptureProcesses = o.CaptureProcesses,
            CaptureFiles = o.CaptureFiles,
            CaptureRegistry = o.CaptureRegistry,
            CaptureNetwork = o.CaptureNetwork,
            TakeSnapshots = o.TakeSnapshots,
            StopWhenTreeExits = stopWhenTreeExits && !o.Interactive,
            NetworkMode = NetworkMode(o.Network),
            Interactive = o.Interactive,
            SimulateUser = o.SimulateUser && !o.Interactive,
            ScreenshotIntervalSeconds = o.CaptureScreenshots ? Math.Clamp(o.ScreenshotIntervalSeconds, 2, 60) : 0,
            MaxScreenshots = Math.Clamp(limits.MaxScreenshots, 0, Protocol.Limits.MaxScreenshots),
            CapturePcap = o.CapturePcap && o.Network == NetworkPolicy.Enabled,
            CollectDroppedFiles = o.CollectDroppedFiles,
            MaxDroppedFiles = Math.Clamp(limits.MaxDroppedFiles, 0, Protocol.Limits.MaxDroppedFiles),
            MaxDroppedFileBytes = Math.Clamp(limits.MaxDroppedFileBytes, 0, Protocol.Limits.MaxFileBytes - 4096),
            DumpMemory = o.DumpMemory,
            MaxMemoryBytes = Math.Max(0, limits.MaxMemoryBytes),
            ChannelKey = Convert.ToBase64String(channelKey),
        };
    }

    public static string NetworkMode(NetworkPolicy policy) => policy switch
    {
        NetworkPolicy.Enabled => "on",
        NetworkPolicy.Simulated => "simulated",
        _ => "off",
    };

    /// <summary>The go signal: which file to run (or which URL to open) and its expected hash.</summary>
    public static GoDto CreateGo(SandboxSessionRequest request, string sampleFileName, DateTimeOffset now) => new()
    {
        SampleFileName = sampleFileName,
        Sha256 = request.Sample.Sha256,
        IssuedAt = now,
        Url = request.Sample.Kind == Core.Samples.FileKind.Url ? request.Sample.Url : null,
    };

    public static byte[] Serialize(ControlDto control) => JsonSerializer.SerializeToUtf8Bytes(control, ProtocolJson.Default.ControlDto);

    /// <summary>
    /// Writes to a temporary name and renames, so the reader never sees a half-written file.
    /// Files in a folder shared with Windows Sandbox can stay open on the host side for a moment
    /// after the guest reads them, so a sharing violation is retried for a while; if the rename
    /// keeps failing, the file is overwritten in place (readers retry a half-written file).
    /// </summary>
    public static void WriteAtomic(string path, byte[] bytes) => WriteAtomic(path, bytes, SharedFileRetry.Default);

    internal static void WriteAtomic(string path, byte[] bytes, SharedFileRetry retry)
    {
        var temp = path + Protocol.TempExtension;
        retry.Run(() => File.WriteAllBytes(temp, bytes));
        if (retry.TryRun(() => File.Move(temp, path, overwrite: true))) return;

        retry.Run(() =>
        {
            using var stream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            stream.SetLength(0);
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        });
        try { File.Delete(temp); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    /// <summary>Opens a file for reading while letting other programs keep it open, retrying sharing violations.</summary>
    public static FileStream OpenShared(string path, SharedFileRetry? retry = null)
    {
        FileStream? stream = null;
        (retry ?? SharedFileRetry.Default).Run(() => stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan));
        return stream!;
    }

    /// <summary>A file name that is safe on the host and in the guest: no folders, no reserved characters, bounded length.</summary>
    public static string SafeFileName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars().Concat(['\\', '/', ':', '*', '?', '"', '<', '>', '|']).ToHashSet();
        var lastSeparator = name.LastIndexOfAny(['\\', '/']);
        var baseName = lastSeparator >= 0 ? name[(lastSeparator + 1)..] : name;
        var cleaned = new string(baseName.Select(c => invalid.Contains(c) || char.IsControl(c) ? '_' : c).ToArray()).Trim(' ', '.');
        if (cleaned.Length == 0) cleaned = "sample.bin";
        return cleaned.Length > 120 ? cleaned[..100] + Path.GetExtension(cleaned) : cleaned;
    }
}
