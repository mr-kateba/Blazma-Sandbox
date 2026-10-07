namespace Blazma.Core.Snapshots;

public sealed record FileEntry(string Path, long Size, DateTimeOffset LastWriteUtc, string? Sha256 = null);

public sealed record RegistryEntry(string Key, string ValueName, string? Data);

/// <summary>
/// The state of the places that matter (user profile, ProgramData, startup locations,
/// services, scheduled tasks) at one moment. Collected inside the sandbox, diffed on the host.
/// </summary>
public sealed record SystemSnapshot
{
    public required DateTimeOffset TakenAt { get; init; }
    public IReadOnlyList<FileEntry> Files { get; init; } = [];
    public IReadOnlyList<RegistryEntry> Registry { get; init; } = [];
    public IReadOnlyList<string> Services { get; init; } = [];
    public IReadOnlyList<string> ScheduledTasks { get; init; } = [];
    public IReadOnlyList<string> StartupItems { get; init; } = [];
}

public sealed record FileChange(string Path, long? OldSize, long? NewSize);

public sealed record RegistryChange(string Key, string ValueName, string? OldData, string? NewData);

public sealed record SnapshotDiff
{
    public IReadOnlyList<FileChange> FilesCreated { get; init; } = [];
    public IReadOnlyList<FileChange> FilesModified { get; init; } = [];
    public IReadOnlyList<FileChange> FilesDeleted { get; init; } = [];
    public IReadOnlyList<RegistryChange> RegistryAdded { get; init; } = [];
    public IReadOnlyList<RegistryChange> RegistryModified { get; init; } = [];
    public IReadOnlyList<RegistryChange> RegistryRemoved { get; init; } = [];
    public IReadOnlyList<string> ServicesAdded { get; init; } = [];
    public IReadOnlyList<string> ServicesRemoved { get; init; } = [];
    public IReadOnlyList<string> TasksAdded { get; init; } = [];
    public IReadOnlyList<string> TasksRemoved { get; init; } = [];
    public IReadOnlyList<string> StartupAdded { get; init; } = [];
    public IReadOnlyList<string> StartupRemoved { get; init; } = [];

    public int TotalChanges =>
        FilesCreated.Count + FilesModified.Count + FilesDeleted.Count +
        RegistryAdded.Count + RegistryModified.Count + RegistryRemoved.Count +
        ServicesAdded.Count + ServicesRemoved.Count + TasksAdded.Count + TasksRemoved.Count +
        StartupAdded.Count + StartupRemoved.Count;
}
