using System.Text;
using System.Text.Json;
using Blazma.Contracts;
using Blazma.Sandbox.Channel;

namespace Blazma.Sandbox.Tests;

public sealed class GuestOutboxSyncTests : IDisposable
{
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("blz-sync");
    private string Staging => Path.Combine(_root.FullName, "staging");
    private string Incoming => Directory.CreateDirectory(Path.Combine(_root.FullName, "incoming")).FullName;

    public void Dispose() => _root.Delete(recursive: true);

    private void Guest(string name, string content) => File.WriteAllText(Path.Combine(Incoming, name), content);
    private string Staged(string name) => File.ReadAllText(Path.Combine(Staging, name));

    [Fact]
    public void Imports_only_complete_protocol_files()
    {
        var sync = new GuestOutboxSync(Staging, 1_000_000);
        Guest(Protocol.HelloFile, "{}");
        Guest(Protocol.EventChunkName(1), "chunk");
        Guest(Protocol.EventChunkName(2) + Protocol.TempExtension, "half");
        Guest("evil.exe", "MZ");
        Guest("events-1.ndjson", "wrong pattern");
        Directory.CreateDirectory(Path.Combine(Incoming, "screen-000001.raw"));

        Assert.Equal(2, sync.Import(Incoming));
        Assert.Equal([Protocol.EventChunkName(1), Protocol.HelloFile], Directory.GetFiles(Staging).Select(Path.GetFileName).Order(StringComparer.Ordinal));
        Assert.Equal(3, sync.RejectedFiles);
        Assert.Contains(sync.Problems, p => p.Contains("evil.exe"));
        Assert.Empty(Directory.EnumerateFileSystemEntries(Incoming));
    }

    [Fact]
    public void Staged_files_are_never_overwritten_except_the_heartbeat()
    {
        var sync = new GuestOutboxSync(Staging, 1_000_000);
        Guest(Protocol.EventChunkName(1), "original");
        Guest(Protocol.HeartbeatFile, "beat-1");
        sync.Import(Incoming);

        Guest(Protocol.EventChunkName(1), "forged later");
        Guest(Protocol.HeartbeatFile, "beat-2");
        Assert.Equal(1, sync.Import(Incoming));

        Assert.Equal("original", Staged(Protocol.EventChunkName(1)));
        Assert.Equal("beat-2", Staged(Protocol.HeartbeatFile));
    }

    [Fact]
    public void Re_syncing_the_same_content_changes_nothing()
    {
        var sync = new GuestOutboxSync(Staging, 1_000_000);
        Guest(Protocol.EventChunkName(1), "chunk");
        Guest(Protocol.DoneFile, "done");
        Assert.Equal(2, sync.Import(Incoming));
        var bytes = sync.BytesImported;

        Guest(Protocol.EventChunkName(1), "chunk");
        Guest(Protocol.DoneFile, "done");
        Assert.Equal(0, sync.Import(Incoming));
        Assert.Equal(bytes, sync.BytesImported);
        Assert.Equal(0, sync.RejectedFiles);
    }

    [Fact]
    public void The_byte_quota_stops_importing()
    {
        var sync = new GuestOutboxSync(Staging, 10);
        Guest(Protocol.EventChunkName(1), "12345678");
        Guest(Protocol.EventChunkName(2), "12345678");
        Assert.Equal(1, sync.Import(Incoming));
        Assert.True(sync.QuotaExceeded);
        Assert.Equal(8, sync.BytesImported);
        Assert.False(File.Exists(Path.Combine(Staging, Protocol.EventChunkName(2))));
    }

    [Fact]
    public void Links_in_the_incoming_copy_are_ignored()
    {
        if (OperatingSystem.IsWindows()) return; // creating symlinks needs elevation on Windows
        var secret = Path.Combine(_root.FullName, "host-secret.txt");
        File.WriteAllText(secret, "host data");
        File.CreateSymbolicLink(Path.Combine(Incoming, Protocol.DoneFile), secret);

        var sync = new GuestOutboxSync(Staging, 1_000_000);
        Assert.Equal(0, sync.Import(Incoming));
        Assert.False(File.Exists(Path.Combine(Staging, Protocol.DoneFile)));
        Assert.Contains(sync.Problems, p => p.Contains("link"));
        Assert.True(File.Exists(secret));
    }

    [Fact]
    public void Select_skips_unexpected_temporary_oversized_and_already_staged_files()
    {
        var sync = new GuestOutboxSync(Staging, 1_000_000);
        File.WriteAllText(Path.Combine(Staging, Protocol.EventChunkName(1)), "x");
        File.WriteAllText(Path.Combine(Staging, Protocol.HeartbeatFile), "x");

        var picked = sync.Select(
        [
            new(Protocol.EventChunkName(1), 1),
            new(Protocol.EventChunkName(2), 5),
            new(Protocol.EventChunkName(3) + Protocol.TempExtension, 5),
            new(Protocol.HeartbeatFile, 5),
            new("..\\..\\Windows\\win.ini", 5),
            new(Protocol.DroppedDataName(1), Protocol.Limits.MaxFileBytes + 1),
            new(Protocol.EventChunkName(2), 5),
        ]);

        Assert.Equal([Protocol.EventChunkName(2), Protocol.HeartbeatFile], picked.Select(f => f.Name));
        Assert.Equal(2, sync.RejectedFiles);
        Assert.Equal([Protocol.EventChunkName(1)], sync.CompletedNames());
    }

    [Fact]
    public void Select_holds_back_done_until_everything_else_fits()
    {
        var sync = new GuestOutboxSync(Staging, 1_000_000);
        var listing = new List<GuestFile> { new(Protocol.DoneFile, 10) };
        listing.AddRange(Enumerable.Range(1, 5).Select(i => new GuestFile(Protocol.EventChunkName(i), 10)));

        var first = sync.Select(listing, maxFiles: 3);
        Assert.Equal([1, 2, 3], first.Select(f => Protocol.TryParseChunkIndex(f.Name, out var i) ? i : -1));

        foreach (var f in first) Guest(f.Name, "0123456789");
        sync.Import(Incoming);
        var second = sync.Select(listing, maxFiles: 3);
        Assert.Equal([Protocol.EventChunkName(4), Protocol.EventChunkName(5), Protocol.DoneFile], second.Select(f => f.Name));
    }

    [Fact]
    public void Select_respects_the_byte_budget()
    {
        var sync = new GuestOutboxSync(Staging, 100);
        var picked = sync.Select([new(Protocol.EventChunkName(1), 60), new(Protocol.EventChunkName(2), 60)]);
        Assert.Single(picked);
        Assert.True(sync.QuotaExceeded);
        Assert.Empty(sync.Select([new(Protocol.EventChunkName(3), 1)]));
    }

    [Fact]
    public void Staged_files_are_read_by_the_outbox_reader()
    {
        var key = SignedFile.NewKey();
        var sync = new GuestOutboxSync(Staging, 1_000_000);
        var line = JsonSerializer.Serialize(new AgentEventDto { Sequence = 1, Action = "ProcessStart", ProcessId = 4, ProcessName = "a.exe", Source = "etw" }, ProtocolJson.Default.AgentEventDto);
        File.WriteAllBytes(Path.Combine(Incoming, Protocol.EventChunkName(1)), SignedFile.Sign(Encoding.UTF8.GetBytes(line), key));
        sync.Import(Incoming);

        var reader = new OutboxReader(Staging, key, 1_000_000);
        Assert.Single(reader.ReadNewEvents(DateTimeOffset.UnixEpoch));
        Assert.Equal(0, reader.RejectedFiles);
    }
}
