using Blazma.Analysis.Engine;
using Blazma.Analysis.Text;
using Blazma.Core.Events;
using Blazma.Core.Processes;
using Blazma.Core.Snapshots;

namespace Blazma.Analysis.Tests;

public class PersistenceAndSnapshotTests
{
    [Theory]
    [InlineData(@"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")]
    [InlineData(@"\REGISTRY\USER\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")]
    [InlineData(@"\REGISTRY\USER\S-1-5-21-1-2-3-1001_Classes\exefile", @"HKCU\Software\Classes\exefile")]
    [InlineData(@"HKEY_LOCAL_MACHINE\System", @"HKLM\System")]
    public void Registry_paths_are_normalized(string raw, string expected) =>
        Assert.Equal(expected, PathRules.NormalizeRegistryKey(raw));

    [Fact]
    public void Device_paths_become_drive_paths() =>
        Assert.Equal(@"C:\Users\x\a.exe", PathRules.NormalizeFilePath(@"\Device\HarddiskVolume3\Users\x\a.exe"));

    [Theory]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "X", PersistenceTechnique.RunKey)]
    [InlineData(@"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "X", PersistenceTechnique.RunKey)]
    [InlineData(@"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", PersistenceTechnique.WinlogonHelper)]
    [InlineData(@"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", "Debugger", PersistenceTechnique.ImageFileExecutionOptions)]
    [InlineData(@"HKLM\System\CurrentControlSet\Services\evil", "ImagePath", PersistenceTechnique.Service)]
    public void Persistence_locations_are_recognized(string key, string value, PersistenceTechnique expected)
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "s.exe", sample: true);
        ev.Reg(10, 100, s, "s.exe", key, value, @"C:\x.exe");
        var graph = ProcessGraph.Build(ev.Events);
        var detection = Assert.Single(PersistenceDetector.Detect(ev.Events, graph));
        Assert.Equal(expected, detection.Technique);
        Assert.True(detection.ByAnalyzedTree);
    }

    [Fact]
    public void Ordinary_registry_writes_are_not_persistence()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "s.exe", sample: true);
        ev.Reg(10, 100, s, "s.exe", @"HKCU\Software\Vendor\App", "Theme", "dark");
        Assert.Empty(PersistenceDetector.Detect(ev.Events, ProcessGraph.Build(ev.Events)));
    }

    [Fact]
    public void Startup_folder_file_is_persistence()
    {
        var ev = new Ev();
        var s = ev.Start(0, 100, 4, "s.exe", sample: true);
        ev.File(10, 100, s, "s.exe", EventAction.FileCreate, @"C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk");
        Assert.Equal(PersistenceTechnique.StartupFolder, Assert.Single(PersistenceDetector.Detect(ev.Events, ProcessGraph.Build(ev.Events))).Technique);
    }

    [Fact]
    public void Snapshot_diff_counts_each_kind_of_change()
    {
        var t = DateTimeOffset.UnixEpoch;
        var before = new SystemSnapshot
        {
            TakenAt = t,
            Files = [new FileEntry(@"C:\a", 1, t), new FileEntry(@"C:\b", 1, t), new FileEntry(@"C:\c", 1, t)],
            Registry = [new RegistryEntry(@"HKCU\K", "v1", "1"), new RegistryEntry(@"HKCU\K", "v2", "2")],
            Services = ["A"],
            ScheduledTasks = [],
            StartupItems = [],
        };
        var after = before with
        {
            Files = [new FileEntry(@"C:\A", 1, t), new FileEntry(@"C:\b", 5, t), new FileEntry(@"C:\d", 1, t)],
            Registry = [new RegistryEntry(@"HKCU\K", "v1", "changed"), new RegistryEntry(@"HKCU\K", "v3", "3")],
            Services = ["A", "B"],
            ScheduledTasks = [@"\T"],
            StartupItems = ["S"],
        };
        var d = SnapshotDiffer.Diff(before, after);
        Assert.Single(d.FilesCreated);
        Assert.Single(d.FilesModified);
        Assert.Single(d.FilesDeleted);
        Assert.Single(d.RegistryAdded);
        Assert.Single(d.RegistryModified);
        Assert.Single(d.RegistryRemoved);
        Assert.Equal(["B"], d.ServicesAdded);
        Assert.Single(d.TasksAdded);
        Assert.Single(d.StartupAdded);
        Assert.Equal(9, d.TotalChanges);
    }
}
