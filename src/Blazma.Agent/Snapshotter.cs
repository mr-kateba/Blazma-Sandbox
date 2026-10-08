using System.Runtime.Versioning;
using System.Security.Cryptography;
using Blazma.Contracts;
using Microsoft.Win32;

namespace Blazma.Agent;

/// <summary>
/// Captures the parts of the system that matter for "what changed": the user profile,
/// ProgramData, startup folders, scheduled task files, services and autorun keys. Scoped
/// on purpose: a full-disk snapshot would be slow and mostly noise.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class Snapshotter
{
    private const int MaxEntries = 150_000;
    private const long MaxHashBytes = 20 * 1024 * 1024;

    private static readonly string[] AutorunKeys =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        @"Software\Microsoft\Windows NT\CurrentVersion\Windows",
    ];

    public static SnapshotDto Take(string excludeRoot)
    {
        var snapshot = new SnapshotDto { TakenAt = DateTimeOffset.UtcNow };
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var roots = new (string Path, int Depth)[]
        {
            (Path.Combine(profile, "Desktop"), 4),
            (Path.Combine(profile, "Documents"), 4),
            (Path.Combine(profile, "Downloads"), 4),
            (Path.Combine(profile, "AppData", "Roaming"), 5),
            (Path.Combine(profile, "AppData", "Local"), 4),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 4),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks"), 6),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"), 3),
        };
        foreach (var (root, depth) in roots) Walk(root, depth, snapshot, excludeRoot);

        foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            foreach (var path in AutorunKeys)
            {
                using var key = Open(hive, path);
                if (key is null) continue;
                foreach (var name in key.GetValueNames())
                {
                    var data = Convert.ToString(key.GetValue(name), System.Globalization.CultureInfo.InvariantCulture);
                    snapshot.Registry.Add(new RegistryEntryDto { Key = (hive == Registry.CurrentUser ? "HKCU\\" : "HKLM\\") + path, ValueName = name, Data = data });
                    if (path.EndsWith(@"\Run", StringComparison.OrdinalIgnoreCase) || path.EndsWith(@"\RunOnce", StringComparison.OrdinalIgnoreCase))
                        snapshot.StartupItems.Add(name);
                }
            }
        }

        using (var services = Open(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services"))
            if (services is not null) snapshot.Services.AddRange(services.GetSubKeyNames());

        var tasks = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
        if (Directory.Exists(tasks))
        {
            foreach (var f in SafeFiles(tasks, recursive: true))
                snapshot.ScheduledTasks.Add("\\" + Path.GetRelativePath(tasks, f));
        }

        foreach (var startup in new[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) })
            if (Directory.Exists(startup))
                snapshot.StartupItems.AddRange(SafeFiles(startup, recursive: false).Select(Path.GetFileName)!);

        return snapshot;
    }

    private static void Walk(string dir, int depth, SnapshotDto snapshot, string excludeRoot)
    {
        if (depth < 0 || snapshot.Files.Count >= MaxEntries || !Directory.Exists(dir)) return;
        if (dir.StartsWith(excludeRoot, StringComparison.OrdinalIgnoreCase)) return;
        foreach (var file in SafeFiles(dir, recursive: false))
        {
            if (snapshot.Files.Count >= MaxEntries) return;
            try
            {
                var info = new FileInfo(file);
                if (info.Attributes.HasFlag(FileAttributes.ReparsePoint)) continue;
                snapshot.Files.Add(new FileEntryDto
                {
                    Path = file,
                    Size = info.Length,
                    LastWriteUtc = info.LastWriteTimeUtc,
                    Sha256 = IsExecutable(file) && info.Length <= MaxHashBytes ? Hash(file) : null,
                });
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        IEnumerable<string> subdirs;
        try { subdirs = Directory.EnumerateDirectories(dir).ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return; }
        foreach (var sub in subdirs)
        {
            try { if (new DirectoryInfo(sub).Attributes.HasFlag(FileAttributes.ReparsePoint)) continue; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
            Walk(sub, depth - 1, snapshot, excludeRoot);
        }
    }

    private static IEnumerable<string> SafeFiles(string dir, bool recursive)
    {
        try
        {
            return Directory.EnumerateFiles(dir, "*", new EnumerationOptions { RecurseSubdirectories = recursive, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }).Take(MaxEntries).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    private static bool IsExecutable(string path) =>
        Path.GetExtension(path).ToLowerInvariant() is ".exe" or ".dll" or ".scr" or ".ps1" or ".vbs" or ".js" or ".bat" or ".cmd" or ".msi" or ".lnk";

    private static string? Hash(string path)
    {
        try
        {
            using var s = File.OpenRead(path);
            return Convert.ToHexStringLower(SHA256.HashData(s));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static RegistryKey? Open(RegistryKey hive, string path)
    {
        try { return hive.OpenSubKey(path); }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException) { return null; }
    }
}
