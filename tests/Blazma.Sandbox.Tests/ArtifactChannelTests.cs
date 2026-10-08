using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Blazma.Contracts;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Samples;
using Blazma.Sandbox.Channel;
using Blazma.Sandbox.Imaging;
using Blazma.Sandbox.Providers.WindowsSandbox;

namespace Blazma.Sandbox.Tests;

public sealed class ArtifactChannelTests : IDisposable
{
    private readonly DirectoryInfo _out = Directory.CreateTempSubdirectory("blz-out");
    private readonly DirectoryInfo _artifacts = Directory.CreateTempSubdirectory("blz-art");
    private readonly byte[] _key = SignedFile.NewKey();

    public void Dispose()
    {
        _out.Delete(true);
        _artifacts.Delete(true);
    }

    private void WriteSigned(string name, byte[] content, byte[]? key = null) => File.WriteAllBytes(Path.Combine(_out.FullName, name), SignedFile.Sign(content, key ?? _key));
    private OutboxReader Reader() => new(_out.FullName, _key, 100_000_000);

    private static byte[] Pixels(int w, int h, byte blue)
    {
        var p = new byte[w * h * 4];
        for (var i = 0; i < p.Length; i += 4) { p[i] = blue; p[i + 1] = 20; p[i + 2] = 30; p[i + 3] = 255; }
        return p;
    }

    [Fact]
    public void Raw_frames_round_trip_and_bad_ones_are_refused()
    {
        var frame = RawFrame.Encode(3, 2, 1500, Pixels(3, 2, 7));
        Assert.True(RawFrame.TryDecode(frame, 1920, 1200, out var w, out var h, out var ms, out var px));
        Assert.Equal((3, 2, 1500L), (w, h, ms));
        Assert.Equal(Pixels(3, 2, 7), px);

        Assert.False(RawFrame.TryDecode(frame, 2, 1200, out _, out _, out _, out _));      // wider than allowed
        Assert.False(RawFrame.TryDecode(frame.AsSpan(0, 14), 1920, 1200, out _, out _, out _, out _)); // pixels cut off
        var lying = (byte[])frame.Clone();
        BinaryPrimitives.WriteUInt16LittleEndian(lying.AsSpan(4), 2); // header claims fewer pixels than the payload holds
        Assert.False(RawFrame.TryDecode(lying, 1920, 1200, out _, out _, out _, out _));
        Assert.False(RawFrame.TryDecode("BLZF"u8.ToArray(), 1920, 1200, out _, out _, out _, out _));
    }

    [Fact]
    public void A_compression_bomb_is_not_inflated_beyond_the_announced_size()
    {
        using var ms = new MemoryStream();
        ms.Write("BLZF"u8);
        Span<byte> dims = stackalloc byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(dims, 10);
        BinaryPrimitives.WriteUInt16LittleEndian(dims[2..], 10);
        ms.Write(dims);
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true)) gz.Write(new byte[50_000_000]);
        Assert.False(RawFrame.TryDecode(ms.ToArray(), 1920, 1200, out _, out _, out _, out _));
    }

    [Fact]
    public void Screenshots_become_host_encoded_png_files()
    {
        WriteSigned(Protocol.ScreenshotName(1), RawFrame.Encode(4, 3, 2000, Pixels(4, 3, 200)));
        WriteSigned(Protocol.ScreenshotName(2), RawFrame.Encode(4, 3, 4000, Pixels(4, 3, 100)), key: SignedFile.NewKey()); // forged
        WriteSigned(Protocol.ScreenshotName(3), "not a frame"u8.ToArray());
        var reader = Reader();
        var shots = reader.ReadNewScreenshots(_artifacts.FullName);

        var shot = Assert.Single(shots);
        Assert.Equal(TimeSpan.FromSeconds(2), shot.RelativeTime);
        var png = File.ReadAllBytes(shot.Path);
        Assert.Equal([0x89, 0x50, 0x4E, 0x47], png[..4]);
        Assert.Equal(4, BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(16)));
        Assert.Equal(3, BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(20)));
        Assert.Equal(1, reader.TamperedFiles);
        Assert.Equal(1, reader.RejectedFiles);
        Assert.Empty(reader.ReadNewScreenshots(_artifacts.FullName)); // already read
    }

    [Fact]
    public void Png_encoder_writes_valid_chunks()
    {
        var png = PngEncoder.EncodeBgra(2, 2, Pixels(2, 2, 1));
        Assert.Equal("IHDR", System.Text.Encoding.ASCII.GetString(png, 12, 4));
        Assert.Equal("IEND", System.Text.Encoding.ASCII.GetString(png, png.Length - 8, 4));
    }

    [Fact]
    public void Dropped_files_must_match_their_signed_description_and_are_stored_defanged()
    {
        var good = "MZ fake program"u8.ToArray();
        WriteDropped(1, good, @"C:\Users\u\AppData\Roaming\upd.exe", Convert.ToHexStringLower(SHA256.HashData(good)));
        WriteDropped(2, "other"u8.ToArray(), @"C:\x.exe", new string('0', 64)); // hash does not match
        var files = Reader().ReadDroppedFiles(_artifacts.FullName, 25);

        var f = Assert.Single(files);
        Assert.Equal(@"C:\Users\u\AppData\Roaming\upd.exe", f.OriginalPath);
        Assert.Equal(".bin", Path.GetExtension(f.StoredPath));
        Assert.Equal(good, File.ReadAllBytes(f.StoredPath));
    }

    [Fact]
    public void Memory_regions_with_unknown_kinds_are_refused()
    {
        var data = new byte[8192];
        data[0] = (byte)'M'; data[1] = (byte)'Z';
        var sha = Convert.ToHexStringLower(SHA256.HashData(data));
        WriteMemory(1, data, "rwx", sha);
        WriteMemory(2, data, "whatever", sha);
        var regions = Reader().ReadMemoryRegions(_artifacts.FullName, 64);
        var r = Assert.Single(regions);
        Assert.Equal(MemoryRegionKind.ReadWriteExecute, r.Kind);
        Assert.Equal(8192, r.Size);
    }

    [Fact]
    public void Only_pcapng_captures_are_accepted()
    {
        WriteSigned(Protocol.PcapFile, "<html>not a capture</html>"u8.ToArray());
        Assert.Null(Reader().ReadPcap(_artifacts.FullName));
        WriteSigned(Protocol.PcapFile, [0x0A, 0x0D, 0x0D, 0x0A, 0x1C, 0, 0, 0, 0x4D, 0x3C, 0x2B, 0x1A, 1, 0]);
        Assert.NotNull(Reader().ReadPcap(_artifacts.FullName));
    }

    [Fact]
    public async Task Extending_and_finishing_write_the_control_file()
    {
        var work = Directory.CreateTempSubdirectory("blz-work");
        var agent = Directory.CreateTempSubdirectory("blz-agent");
        try
        {
            var sample = new SampleInfo { FileName = "a.exe", Size = 1, Sha256 = new string('a', 64), Sha1 = new string('b', 40), Kind = FileKind.Executable };
            var request = new SandboxSessionRequest(Guid.NewGuid(), "a.exe", sample, new AnalysisOptions { Duration = TimeSpan.FromMinutes(2) });
            var session = new WindowsSandboxSession(request, new WindowsSandboxOptions { WorkRoot = work.FullName, AgentFolder = agent.FullName }, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
            await session.CreateEnvironmentAsync(CancellationToken.None);
            var control = Path.Combine(work.FullName, request.AnalysisId.ToString("N"), "in", Protocol.ControlFile);

            await session.ExtendAsync(TimeSpan.FromMinutes(3), CancellationToken.None);
            var first = JsonSerializer.Deserialize(File.ReadAllBytes(control), ProtocolJson.Default.ControlDto)!;
            Assert.Equal((1, 300, false), (first.Sequence, first.DurationSeconds, first.FinishNow));

            await session.ExtendAsync(TimeSpan.FromHours(5), CancellationToken.None);
            Assert.Equal((int)AnalysisOptions.MaxDuration.TotalSeconds, JsonSerializer.Deserialize(File.ReadAllBytes(control), ProtocolJson.Default.ControlDto)!.DurationSeconds);

            await session.FinishNowAsync(CancellationToken.None);
            var last = JsonSerializer.Deserialize(File.ReadAllBytes(control), ProtocolJson.Default.ControlDto)!;
            Assert.True(last.FinishNow);
            Assert.Equal(3, last.Sequence);

            var config = JsonSerializer.Deserialize(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(control)!, Protocol.SessionFile)), ProtocolJson.Default.SessionConfigDto)!;
            Assert.Equal("off", config.NetworkMode);
            Assert.True(config.SimulateUser);
            await session.ShutdownAsync(CancellationToken.None);
        }
        finally
        {
            if (work.Exists) work.Delete(true);
            agent.Delete(true);
        }
    }

    [Fact]
    public void Session_config_never_enables_capture_without_the_real_network()
    {
        var sample = new SampleInfo { FileName = "a.exe", Size = 1, Sha256 = new string('a', 64), Sha1 = new string('b', 40), Kind = FileKind.Executable };
        var simulated = new SandboxSessionRequest(Guid.NewGuid(), "a", sample, new AnalysisOptions { Network = NetworkPolicy.Simulated, CapturePcap = true, Interactive = true });
        var config = ChannelFiles.CreateConfig(simulated, SignedFile.NewKey(), stopWhenTreeExits: true);
        Assert.Equal("simulated", config.NetworkMode);
        Assert.False(config.CapturePcap);
        Assert.False(config.StopWhenTreeExits); // interactive runs never end on their own
        Assert.False(config.SimulateUser);
    }

    private void WriteDropped(int index, byte[] data, string path, string sha)
    {
        WriteSigned(Protocol.DroppedDataName(index), data);
        WriteSigned(Protocol.DroppedMetaName(index), JsonSerializer.SerializeToUtf8Bytes(new DroppedFileDto { OriginalPath = path, ProcessName = "s.exe", ProcessId = 5, Size = data.Length, Sha256 = sha }, ProtocolJson.Default.DroppedFileDto));
    }

    private void WriteMemory(int index, byte[] data, string kind, string sha)
    {
        WriteSigned(Protocol.MemoryDataName(index), data);
        WriteSigned(Protocol.MemoryMetaName(index), JsonSerializer.SerializeToUtf8Bytes(new MemoryRegionDto { ProcessId = 5, ProcessName = "s.exe", BaseAddress = 0x400000, Size = data.Length, Protection = "RWX", Kind = kind, Sha256 = sha }, ProtocolJson.Default.MemoryRegionDto));
    }
}
