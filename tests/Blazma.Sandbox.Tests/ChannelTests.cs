using System.Text;
using System.Text.Json;
using Blazma.Contracts;
using Blazma.Core.Events;
using Blazma.Sandbox.Channel;

namespace Blazma.Sandbox.Tests;

public sealed class ChannelTests : IDisposable
{
    private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory("blz-out");
    private readonly byte[] _key = SignedFile.NewKey();
    private static readonly DateTimeOffset Start = DateTimeOffset.UnixEpoch;

    public void Dispose() => _dir.Delete(recursive: true);

    private void WriteChunk(int index, IEnumerable<string> lines, byte[]? key = null)
    {
        var content = Encoding.UTF8.GetBytes(string.Join("\n", lines));
        File.WriteAllBytes(Path.Combine(_dir.FullName, Protocol.EventChunkName(index)), SignedFile.Sign(content, key ?? _key));
    }

    private static string Line(string action, string? target = null, Dictionary<string, string>? d = null, string proc = "a.exe") =>
        JsonSerializer.Serialize(new AgentEventDto { Sequence = 1, RelativeMs = 10, Action = action, ProcessId = 10, ProcessName = proc, Target = target, Details = d, Source = "etw" }, ProtocolJson.Default.AgentEventDto);

    [Fact]
    public void Signed_files_verify_and_tampering_is_detected()
    {
        var signed = SignedFile.Sign("hello"u8, _key);
        Assert.Equal("hello"u8.ToArray(), SignedFile.Verify(signed, _key));
        signed[0] ^= 1;
        Assert.Null(SignedFile.Verify(signed, _key));
        Assert.Null(SignedFile.Verify(SignedFile.Sign("hello"u8, SignedFile.NewKey()), _key));
        Assert.Null(SignedFile.Verify("no trailer"u8, _key));
    }

    [Fact]
    public void Reads_chunks_in_order_and_resequences_on_the_host()
    {
        WriteChunk(1, [Line("ProcessStart", null), Line("FileCreate", @"\Device\HarddiskVolume2\Users\u\a.txt")]);
        WriteChunk(2, [Line("RegistryValueSet", @"\REGISTRY\MACHINE\SOFTWARE\X")]);
        var reader = new OutboxReader(_dir.FullName, _key, 1_000_000);

        var events = reader.ReadNewEvents(Start);
        Assert.Equal([1L, 2L, 3L], events.Select(e => e.Sequence));
        Assert.Equal(@"C:\Users\u\a.txt", events[1].Target);
        Assert.Equal(@"HKLM\SOFTWARE\X", events[2].Target);
        Assert.Empty(reader.ReadNewEvents(Start));
    }

    [Fact]
    public void A_gap_in_chunk_numbers_waits_for_the_missing_chunk()
    {
        WriteChunk(2, [Line("FileCreate", "x")]);
        var reader = new OutboxReader(_dir.FullName, _key, 1_000_000);
        Assert.Empty(reader.ReadNewEvents(Start));
        WriteChunk(1, [Line("FileCreate", "y")]);
        Assert.Equal(2, reader.ReadNewEvents(Start).Count);
    }

    [Fact]
    public void Forged_chunks_are_discarded_and_counted()
    {
        WriteChunk(1, [Line("FileCreate", "x")], key: SignedFile.NewKey());
        var reader = new OutboxReader(_dir.FullName, _key, 1_000_000);
        Assert.Empty(reader.ReadNewEvents(Start));
        Assert.Equal(1, reader.TamperedFiles);
    }

    [Fact]
    public void Malformed_lines_and_unknown_actions_are_skipped()
    {
        WriteChunk(1, ["{not json", Line("FormatDisk", "C:"), Line("ProcessStart"), "", "null"]);
        var reader = new OutboxReader(_dir.FullName, _key, 1_000_000);
        var events = reader.ReadNewEvents(Start);
        Assert.Single(events);
        Assert.Equal(3, reader.MalformedLines);
    }

    [Fact]
    public void Oversized_strings_and_control_characters_are_neutralized()
    {
        var huge = new string('A', Protocol.Limits.MaxStringLength * 2);
        var details = Enumerable.Range(0, 100).ToDictionary(i => $"k{i}", i => "v");
        WriteChunk(1, [Line("FileCreate", "evil\u001b[31mname" + huge, details)]);
        var e = new OutboxReader(_dir.FullName, _key, 10_000_000).ReadNewEvents(Start).Single();
        Assert.True(e.Target!.Length <= Protocol.Limits.MaxStringLength);
        Assert.DoesNotContain('\u001b', e.Target);
        Assert.True(e.Details.Count <= Protocol.Limits.MaxDetails);
    }

    [Fact]
    public void Unexpected_files_are_ignored_and_reported()
    {
        File.WriteAllText(Path.Combine(_dir.FullName, "payload.exe"), "MZ");
        File.WriteAllText(Path.Combine(_dir.FullName, "..events-000001.ndjson"), "x");
        var reader = new OutboxReader(_dir.FullName, _key, 1_000_000);
        Assert.Empty(reader.ReadNewEvents(Start));
        Assert.Equal(2, reader.RejectedFiles);
    }

    [Fact]
    public void Links_are_never_followed()
    {
        if (OperatingSystem.IsWindows()) return; // creating symlinks needs elevation on Windows
        var secret = Path.Combine(Path.GetTempPath(), $"blz-secret-{Guid.NewGuid():N}.txt");
        File.WriteAllBytes(secret, SignedFile.Sign(Encoding.UTF8.GetBytes(Line("FileCreate", "leak")), _key));
        try
        {
            File.CreateSymbolicLink(Path.Combine(_dir.FullName, Protocol.EventChunkName(1)), secret);
            var reader = new OutboxReader(_dir.FullName, _key, 1_000_000);
            Assert.Empty(reader.ReadNewEvents(Start));
            Assert.Equal(1, reader.RejectedFiles);
        }
        finally { File.Delete(secret); }
    }

    [Fact]
    public void Output_quota_stops_reading()
    {
        WriteChunk(1, Enumerable.Repeat(Line("FileCreate", "x"), 200));
        var reader = new OutboxReader(_dir.FullName, _key, quotaBytes: 100);
        Assert.Empty(reader.ReadNewEvents(Start));
        Assert.True(reader.QuotaExceeded);
    }

    [Fact]
    public void Only_protocol_file_names_are_allowed()
    {
        Assert.True(Protocol.IsAllowedOutboxName("events-000001.ndjson"));
        Assert.True(Protocol.IsAllowedOutboxName("done.json"));
        Assert.False(Protocol.IsAllowedOutboxName("events-1.ndjson"));
        Assert.False(Protocol.IsAllowedOutboxName("../done.json"));
        Assert.False(Protocol.IsAllowedOutboxName("session.json"));
    }

    [Fact]
    public void Process_keys_use_the_process_start_time()
    {
        var line = JsonSerializer.Serialize(new AgentEventDto { Action = "ProcessStart", ProcessId = 42, ProcessStartMs = 1500, ProcessName = "x.exe", Source = "etw" }, ProtocolJson.Default.AgentEventDto);
        WriteChunk(1, [line]);
        var e = new OutboxReader(_dir.FullName, _key, 1_000_000).ReadNewEvents(Start).Single();
        Assert.Equal(new ProcessKey(42, TimeSpan.FromMilliseconds(1500).Ticks), e.Process);
    }
}
