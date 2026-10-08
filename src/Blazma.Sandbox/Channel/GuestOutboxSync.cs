using Blazma.Contracts;

namespace Blazma.Sandbox.Channel;

/// <summary>A file as listed in the guest's <c>out</c> folder. The length is a claim by the guest, checked again on import.</summary>
public sealed record GuestFile(string Name, long Length);

/// <summary>
/// Brings a virtual machine's <c>out</c> folder to the host for <see cref="OutboxReader"/>.
/// A provider lists the guest folder, fetches what <see cref="Select"/> picks into an empty
/// incoming folder, and calls <see cref="Import"/>, which moves complete files into the staging
/// folder the reader watches. Everything the guest says is hostile:
/// <list type="bullet">
/// <item>only names in <see cref="Protocol.IsAllowedOutboxName"/> are fetched or imported; <c>.tmp</c> files are never complete;</item>
/// <item>links, folders and unexpected names are dropped and reported;</item>
/// <item>a file already staged is never overwritten (except the heartbeat, which the agent rewrites);</item>
/// <item>per-file and per-analysis byte quotas are enforced before fetching and again on import;</item>
/// <item>re-running a sync with the same guest content changes nothing.</item>
/// </list>
/// </summary>
public sealed class GuestOutboxSync
{
    /// <summary>Most files fetched in one round, so a single command line stays short.</summary>
    public const int DefaultMaxFilesPerRound = 64;

    private const int MaxProblems = 50;
    private readonly string _staging;
    private readonly long _quotaBytes;
    private readonly HashSet<string> _reported = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _problems = [];

    public GuestOutboxSync(string stagingFolder, long quotaBytes)
    {
        _staging = Directory.CreateDirectory(stagingFolder).FullName;
        _quotaBytes = quotaBytes;
    }

    public string StagingFolder => _staging;
    public long BytesImported { get; private set; }
    public long RemainingBytes => Math.Max(0, _quotaBytes - BytesImported);
    public bool QuotaExceeded { get; private set; }
    public int RejectedFiles { get; private set; }
    public IReadOnlyList<string> Problems => _problems;

    /// <summary>The agent rewrites these in place; a newer complete copy replaces the staged one.</summary>
    public static bool IsReplaceable(string name) => name == Protocol.HeartbeatFile;

    /// <summary>True when the file is worth fetching: an allowed, complete name that is not staged yet (or is replaceable).</summary>
    public bool IsWanted(string name) =>
        Protocol.IsAllowedOutboxName(name)
        && (IsReplaceable(name) || !File.Exists(Path.Combine(_staging, name)));

    /// <summary>Names already staged that never change again; a guest-side copy may skip them.</summary>
    public IReadOnlyList<string> CompletedNames()
    {
        try
        {
            return Directory.EnumerateFiles(_staging)
                .Select(Path.GetFileName)
                .OfType<string>()
                .Where(n => Protocol.IsAllowedOutboxName(n) && !IsReplaceable(n))
                .Order(StringComparer.Ordinal)
                .ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    /// <summary>
    /// Chooses which listed files to fetch this round, in protocol order, within the byte budget.
    /// <c>done.json</c> is held back until everything else wanted fits in the same round, so the
    /// reader never sees the done marker before the last events.
    /// </summary>
    public IReadOnlyList<GuestFile> Select(IEnumerable<GuestFile> listing, int maxFiles = DefaultMaxFilesPerRound)
    {
        if (QuotaExceeded) return [];
        var wanted = new List<GuestFile>();
        foreach (var file in listing.DistinctBy(f => f.Name, StringComparer.OrdinalIgnoreCase))
        {
            if (file.Name.EndsWith(Protocol.TempExtension, StringComparison.Ordinal)) continue;
            if (!Protocol.IsAllowedOutboxName(file.Name))
            {
                Reject(file.Name, $"Unexpected file in the guest output folder was ignored: {Truncate(file.Name)}");
                continue;
            }
            if (file.Length < 0 || file.Length > Protocol.Limits.MaxFileBytes)
            {
                Reject(file.Name, $"{file.Name}: larger than {Protocol.Limits.MaxFileBytes} bytes in the guest; not copied.");
                continue;
            }
            if (IsWanted(file.Name)) wanted.Add(file);
        }

        var ordered = wanted.OrderBy(f => f.Name == Protocol.DoneFile ? 1 : 0).ThenBy(f => f.Name, StringComparer.Ordinal).ToList();
        var selected = new List<GuestFile>();
        long budget = RemainingBytes;
        var leftOut = false;
        foreach (var file in ordered)
        {
            if (file.Name == Protocol.DoneFile && leftOut) break;
            if (selected.Count >= maxFiles) { leftOut = true; continue; }
            if (file.Length > budget)
            {
                QuotaExceeded = true;
                AddProblem("The virtual machine wrote more data than the configured quota; copying stopped.");
                leftOut = true;
                break;
            }
            budget -= file.Length;
            selected.Add(file);
        }
        return selected;
    }

    /// <summary>
    /// Moves complete, allowed files from <paramref name="incomingFolder"/> into the staging folder
    /// and empties the incoming folder. Returns the number of files imported.
    /// </summary>
    public int Import(string incomingFolder)
    {
        var imported = 0;
        if (!Directory.Exists(incomingFolder)) return 0;
        try
        {
            foreach (var path in Directory.EnumerateFileSystemEntries(incomingFolder).Take(10_000).ToList())
            {
                var name = Path.GetFileName(path);
                if (TryImport(path, name)) imported++;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            AddProblem($"The incoming copy could not be read: {ex.GetType().Name}.");
        }
        finally
        {
            Clear(incomingFolder);
        }
        return imported;
    }

    private bool TryImport(string path, string name)
    {
        FileInfo info;
        try { info = new FileInfo(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }

        if (!info.Exists || info.Attributes.HasFlag(FileAttributes.Directory))
        {
            Reject(name, $"Unexpected folder in the guest output was ignored: {Truncate(name)}");
            return false;
        }
        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint) || info.LinkTarget is not null)
        {
            Reject(name, $"{Truncate(name)}: is a link; ignored.");
            return false;
        }
        if (name.EndsWith(Protocol.TempExtension, StringComparison.Ordinal)) return false;
        if (!Protocol.IsAllowedOutboxName(name))
        {
            Reject(name, $"Unexpected file in the guest output folder was ignored: {Truncate(name)}");
            return false;
        }

        var target = Path.Combine(_staging, name);
        var replace = IsReplaceable(name);
        if (!replace && File.Exists(target)) return false;
        if (info.Length > Protocol.Limits.MaxFileBytes)
        {
            Reject(name, $"{name}: larger than {Protocol.Limits.MaxFileBytes} bytes; ignored.");
            return false;
        }
        if (QuotaExceeded || info.Length > RemainingBytes)
        {
            QuotaExceeded = true;
            AddProblem("The virtual machine wrote more data than the configured quota; copying stopped.");
            return false;
        }

        var temp = target + Protocol.TempExtension;
        try
        {
            File.Move(path, temp, overwrite: true);
            File.Move(temp, target, overwrite: replace);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TryDelete(temp);
            return false;
        }
        BytesImported += info.Length;
        return true;
    }

    private void Reject(string name, string problem)
    {
        if (!_reported.Add(name)) return;
        RejectedFiles++;
        AddProblem(problem);
    }

    private void AddProblem(string problem)
    {
        if (_problems.Count < MaxProblems && !_problems.Contains(problem)) _problems.Add(problem);
    }

    private static void Clear(string folder)
    {
        try
        {
            foreach (var entry in new DirectoryInfo(folder).EnumerateFileSystemInfos())
            {
                try
                {
                    if (entry is DirectoryInfo dir && entry.LinkTarget is null) dir.Delete(recursive: true);
                    else entry.Delete();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static string Truncate(string s)
    {
        var clean = new string(s.Select(c => char.IsControl(c) ? '�' : c).ToArray());
        return clean.Length > 80 ? clean[..80] + "…" : clean;
    }
}
