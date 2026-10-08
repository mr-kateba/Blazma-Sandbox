using Blazma.Agent.Capture;
using Blazma.Agent.Collect;
using Blazma.Agent.Simulation;

namespace Blazma.Agent.Tests;


public class SelectionTests
{
    private const int Push = 0, Checkbox = 3, Radio = 9;

    [Theory]
    [InlineData("&Next >", Push, "Advance")]
    [InlineData("Install", Push, "Advance")]
    [InlineData("I &Agree", Push, "Advance")]
    [InlineData("OK", Push, "Advance")]
    [InlineData("التالي", Push, "Advance")]
    [InlineData("Cancel", Push, "None")]
    [InlineData("< Back", Push, "None")]
    [InlineData("No", Push, "None")]
    [InlineData("Uninstall", Push, "None")]
    [InlineData("Browse...", Push, "None")]
    [InlineData("إلغاء", Push, "None")]
    [InlineData("I accept the agreement", Radio, "Accept")]
    [InlineData("I do not accept the agreement", Radio, "None")]
    [InlineData("I agree to the terms", Checkbox, "Accept")]
    [InlineData("Send anonymous usage data", Checkbox, "None")]
    [InlineData("أوافق على الشروط", Radio, "Accept")]
    [InlineData("لا أوافق", Radio, "None")]
    public void Simulated_user_presses_only_forward_buttons(string label, int type, string expected)
    {
        Assert.Equal(expected, InstallerButtons.Decide(label, type).ToString());
    }

    [Fact]
    public void Pe_regions_and_unbacked_images_come_first()
    {
        const uint Private = 0x20000, Image = 0x1000000, Rx = 0x20, Rwx = 0x40, Rw = 0x04;
        var regions = new[]
        {
            new RegionInfo(0x1000, 64 * 1024, Rx, Private, true, false),       // JIT-like code
            new RegionInfo(0x2000, 64 * 1024, Rwx, Private, true, false),      // RWX
            new RegionInfo(0x3000, 128 * 1024, Rx, Image, false, true),        // hollowed image
            new RegionInfo(0x4000, 32 * 1024, Rwx, Private, true, true),       // unpacked PE
            new RegionInfo(0x5000, 64 * 1024, Rx, Image, true, true),          // normal mapped DLL: skipped
            new RegionInfo(0x6000, 64 * 1024, Rw, Private, true, true),        // not executable: skipped
            new RegionInfo(0x7000, 1024, Rwx, Private, true, true),            // too small: skipped
        };
        var picked = RegionSelector.Select(regions, 10, 1024 * 1024);
        Assert.Equal([0x3000ul, 0x4000ul, 0x2000ul, 0x1000ul], picked.Select(p => p.Region.Base));
        Assert.Equal("unbacked-image", picked[0].Kind);
        Assert.Equal("rwx", picked[1].Kind);
        Assert.Equal("RWX", picked[1].Protection);
        Assert.Equal("private-exec", picked[3].Kind);
        Assert.Equal(2, RegionSelector.Select(regions, 2, 1024 * 1024).Count);
        Assert.All(RegionSelector.Select(regions, 10, 8192), p => Assert.True(p.Region.Size <= 8192));
    }

    [Fact]
    public void Dropped_files_put_programs_first_and_skip_noise()
    {
        var facts = new Dictionary<string, (long Size, bool IsPe)?>(StringComparer.OrdinalIgnoreCase)
        {
            [@"C:\Users\u\AppData\Roaming\x\upd.exe"] = (50_000, true),
            [@"C:\Users\u\AppData\Roaming\x\run.ps1"] = (300, false),
            [@"C:\Users\u\AppData\Roaming\x\config.dat"] = (2_000, false),
            [@"C:\Users\u\AppData\Roaming\x\huge.bin"] = (5_000_000, false),
            [@"C:\Windows\Prefetch\UPD.EXE-1.pf"] = (2_000, false),
            [@"C:\Blazma\out\events-000001.ndjson"] = (2_000, false),
            [@"C:\Users\u\AppData\Roaming\x\too-big.exe"] = (100_000_000, true),
            [@"C:\Users\u\AppData\Roaming\x\gone.exe"] = null,
        };
        var candidates = facts.Keys.Select(p => new DropCandidate(p, 10, "sample.exe"));
        var picked = DroppedFileCollector.Prioritize(candidates, p => facts[p], 32 * 1024 * 1024, [@"c:\blazma\out"]);
        Assert.Equal([@"C:\Users\u\AppData\Roaming\x\upd.exe", @"C:\Users\u\AppData\Roaming\x\run.ps1", @"C:\Users\u\AppData\Roaming\x\config.dat"], picked.Select(p => p.Path));
    }

    [Fact]
    public void Frames_are_downscaled_by_averaging()
    {
        var w = 4; var h = 2;
        var pixels = new byte[w * h * 4];
        for (var i = 0; i < w * h; i++) { pixels[i * 4] = (byte)(i % 2 == 0 ? 0 : 200); pixels[i * 4 + 3] = 255; }
        var (small, sw, sh) = FrameScaler.Downscale(pixels, w, h, 2);
        Assert.Equal((2, 1), (sw, sh));
        Assert.Equal(100, small[0]);
        var (same, w2, _) = FrameScaler.Downscale(pixels, w, h, 1280);
        Assert.Same(pixels, same);
        Assert.Equal(w, w2);
    }

    [Fact]
    public void Control_file_extends_but_never_shortens()
    {
        var dir = Directory.CreateTempSubdirectory("blz-ctl");
        try
        {
            var watcher = new ControlWatcher(dir.FullName, 120);
            void Write(int seq, int seconds, bool finish) => File.WriteAllBytes(Path.Combine(dir.FullName, Contracts.Protocol.ControlFile),
                System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new Contracts.ControlDto { Sequence = seq, DurationSeconds = seconds, FinishNow = finish }, Contracts.ProtocolJson.Default.ControlDto));

            Write(1, 300, false);
            watcher.Poll();
            Assert.Equal(300, watcher.DurationSeconds);
            Write(1, 900, false); // same sequence: ignored
            watcher.Poll();
            Assert.Equal(300, watcher.DurationSeconds);
            Write(2, 60, false);  // shorter: ignored
            watcher.Poll();
            Assert.Equal(300, watcher.DurationSeconds);
            Write(3, 99_999, false);
            watcher.Poll();
            Assert.Equal(1800, watcher.DurationSeconds);
            Assert.False(watcher.FinishRequested);
            Write(4, 1800, true);
            watcher.Poll();
            Assert.True(watcher.FinishRequested);
        }
        finally
        {
            dir.Delete(true);
        }
    }
}
