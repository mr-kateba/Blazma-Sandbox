using Blazma.Core.Snapshots;

namespace Blazma.Analysis.Engine;

public static class SnapshotDiffer
{
    public static SnapshotDiff Diff(SystemSnapshot before, SystemSnapshot after)
    {
        var oldFiles = before.Files.GroupBy(f => f.Path, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        var newFiles = after.Files.GroupBy(f => f.Path, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var created = newFiles.Values.Where(f => !oldFiles.ContainsKey(f.Path)).Select(f => new FileChange(f.Path, null, f.Size));
        var deleted = oldFiles.Values.Where(f => !newFiles.ContainsKey(f.Path)).Select(f => new FileChange(f.Path, f.Size, null));
        var modified = newFiles.Values
            .Where(f => oldFiles.TryGetValue(f.Path, out var o) && (o.Size != f.Size || o.LastWriteUtc != f.LastWriteUtc || (o.Sha256 is not null && f.Sha256 is not null && o.Sha256 != f.Sha256)))
            .Select(f => new FileChange(f.Path, oldFiles[f.Path].Size, f.Size));

        static string RegKey(RegistryEntry r) => r.Key + "\\\\" + r.ValueName;
        var oldReg = before.Registry.GroupBy(RegKey, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        var newReg = after.Registry.GroupBy(RegKey, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        return new SnapshotDiff
        {
            FilesCreated = Sorted(created),
            FilesModified = Sorted(modified),
            FilesDeleted = Sorted(deleted),
            RegistryAdded = newReg.Where(kv => !oldReg.ContainsKey(kv.Key)).Select(kv => new RegistryChange(kv.Value.Key, kv.Value.ValueName, null, kv.Value.Data)).OrderBy(r => r.Key, StringComparer.OrdinalIgnoreCase).ToList(),
            RegistryRemoved = oldReg.Where(kv => !newReg.ContainsKey(kv.Key)).Select(kv => new RegistryChange(kv.Value.Key, kv.Value.ValueName, kv.Value.Data, null)).OrderBy(r => r.Key, StringComparer.OrdinalIgnoreCase).ToList(),
            RegistryModified = newReg.Where(kv => oldReg.TryGetValue(kv.Key, out var o) && !string.Equals(o.Data, kv.Value.Data, StringComparison.Ordinal))
                .Select(kv => new RegistryChange(kv.Value.Key, kv.Value.ValueName, oldReg[kv.Key].Data, kv.Value.Data)).OrderBy(r => r.Key, StringComparer.OrdinalIgnoreCase).ToList(),
            ServicesAdded = Added(before.Services, after.Services),
            ServicesRemoved = Added(after.Services, before.Services),
            TasksAdded = Added(before.ScheduledTasks, after.ScheduledTasks),
            TasksRemoved = Added(after.ScheduledTasks, before.ScheduledTasks),
            StartupAdded = Added(before.StartupItems, after.StartupItems),
            StartupRemoved = Added(after.StartupItems, before.StartupItems),
        };
    }

    private static List<FileChange> Sorted(IEnumerable<FileChange> changes) =>
        changes.OrderBy(c => c.Path, StringComparer.OrdinalIgnoreCase).ToList();

    private static List<string> Added(IEnumerable<string> before, IEnumerable<string> after)
    {
        var set = new HashSet<string>(before, StringComparer.OrdinalIgnoreCase);
        return after.Where(a => !set.Contains(a)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(a => a, StringComparer.OrdinalIgnoreCase).ToList();
    }
}
