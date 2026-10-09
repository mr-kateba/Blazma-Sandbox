using System.Diagnostics;
using System.Text.Json;
using Blazma.Core.Abstractions;
using Blazma.Analysis.Archives;
using Blazma.Analysis.Yara;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Static;

/// <summary>Options passed from the host to the static-analysis helper on its command line.</summary>
public sealed record StaticWorkerOptions(bool DetectCapabilities = true, string? YaraFolder = null, string? ArchivePassword = null);

/// <summary>
/// Runs static analysis in a separate, short-lived copy of the calling executable, so a parser
/// bug triggered by a hostile file cannot reach the UI or command-line process. The sample is
/// only read, never executed. Both sides of the exchange live here: the client that starts the
/// helper and the helper's entry point.
/// </summary>
public static class StaticWorker
{
    public const string Flag = "--static-worker";
    private const string NoCapabilitiesFlag = "--no-capabilities";
    private const string YaraFlag = "--yara";
    private const string PasswordFlag = "--password";

    /// <summary>Second helper mode: extracts one archive entry (archives are hostile input too).</summary>
    public const string ExtractFlag = "--extract-worker";

    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(90);

    /// <summary>True when the process was started as the helper (see <see cref="RunAsync"/>).</summary>
    public static bool IsWorkerInvocation(IReadOnlyList<string> args) =>
        (args.Count >= 2 && args[0] == Flag) || (args.Count >= 4 && args[0] == ExtractFlag);

    /// <summary>
    /// Analyzes <paramref name="path"/> in a helper process. <paramref name="managedEntryDll"/> is
    /// the main assembly to pass when the host itself runs under "dotnet" (development builds).
    /// </summary>
    public static async Task<StaticReport> AnalyzeAsync(
        string path,
        StaticWorkerOptions options,
        JsonSerializerOptions json,
        string managedEntryDll,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        var stdout = await RunHelperAsync(BuildArguments(path, options), managedEntryDll, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<StaticReport>(stdout, json) ?? throw new InvalidDataException("Empty static report.");
    }

    /// <summary>
    /// Extracts one entry of an archive in a helper process into <paramref name="destinationFolder"/>
    /// and returns the extracted file's path. The entry is written, never opened or run.
    /// </summary>
    public static async Task<string> ExtractAsync(
        string archivePath,
        string entryPath,
        string? password,
        string destinationFolder,
        string managedEntryDll,
        CancellationToken cancellationToken)
    {
        var args = new List<string> { ExtractFlag, archivePath, entryPath, destinationFolder };
        if (!string.IsNullOrEmpty(password)) { args.Add(PasswordFlag); args.Add(password); }
        var output = (await RunHelperAsync(args, managedEntryDll, cancellationToken).ConfigureAwait(false)).Trim();
        var full = Path.GetFullPath(output);
        var root = Path.GetFullPath(destinationFolder);
        if (!full.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || !File.Exists(full))
            throw new InvalidDataException("The archive helper returned an unexpected path.");
        return full;
    }

    private static async Task<string> RunHelperAsync(IReadOnlyList<string> args, string managedEntryDll, CancellationToken cancellationToken)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot locate the Blazma executable.");
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        if (Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            psi.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, managedEntryDll));
        foreach (var arg in args) psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("The analysis helper did not start.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Timeout);
        try
        {
            var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            if (process.ExitCode != 0) throw new InvalidOperationException((await stderr.ConfigureAwait(false)).Trim());
            return await stdout.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            throw;
        }
    }

    public static IReadOnlyList<string> BuildArguments(string path, StaticWorkerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var args = new List<string> { Flag, path };
        if (!options.DetectCapabilities) args.Add(NoCapabilitiesFlag);
        if (!string.IsNullOrWhiteSpace(options.YaraFolder)) { args.Add(YaraFlag); args.Add(options.YaraFolder); }
        if (!string.IsNullOrEmpty(options.ArchivePassword)) { args.Add(PasswordFlag); args.Add(options.ArchivePassword); }
        return args;
    }

    /// <summary>Parses the helper's arguments; null when they are not a valid helper invocation.</summary>
    public static (string Path, StaticWorkerOptions Options)? ParseArguments(IReadOnlyList<string> args)
    {
        if (args.Count < 2 || args[0] != Flag) return null;
        var options = new StaticWorkerOptions();
        for (var i = 2; i < args.Count; i++)
        {
            switch (args[i])
            {
                case NoCapabilitiesFlag: options = options with { DetectCapabilities = false }; break;
                case YaraFlag when i + 1 < args.Count: options = options with { YaraFolder = args[++i] }; break;
                case PasswordFlag when i + 1 < args.Count: options = options with { ArchivePassword = args[++i] }; break;
                default: return null;
            }
        }
        return (args[1], options);
    }

    /// <summary>The helper's entry point: analyzes one file and writes the report as JSON to stdout.</summary>
    public static async Task<int> RunAsync(IReadOnlyList<string> args, JsonSerializerOptions json, Func<string, IYaraScanner?>? loadYara = null)
    {
        if (args.Count >= 4 && args[0] == ExtractFlag) return await RunExtractAsync(args).ConfigureAwait(false);
        var parsed = ParseArguments(args);
        if (parsed is not { } p)
        {
            await Console.Error.WriteLineAsync("Invalid static worker arguments.").ConfigureAwait(false);
            return 2;
        }
        try
        {
            using var cts = new CancellationTokenSource(Timeout - TimeSpan.FromSeconds(10));
            loadYara ??= folder => YaraRuleSet.LoadFolder(folder);
            var yara = p.Options.YaraFolder is { } folder && Directory.Exists(folder) ? loadYara(folder) : null;
            var analyzer = new StaticAnalyzer(yara, p.Options.DetectCapabilities)
            {
                ArchivePasswords = p.Options.ArchivePassword is { Length: > 0 } pw
                    ? [pw, .. ArchiveReader.DefaultPasswords.Where(x => x != pw)]
                    : ArchiveReader.DefaultPasswords,
            };
            var report = await analyzer.AnalyzeAsync(p.Path, cts.Token).ConfigureAwait(false);
            if (yara is { LoadErrors.Count: > 0 })
                report = report with { Warnings = [.. report.Warnings, $"{yara.LoadErrors.Count} YARA rule(s) could not be loaded; see the Intelligence page."] };
            await using var stdout = Console.OpenStandardOutput();
            await JsonSerializer.SerializeAsync(stdout, report, json, cts.Token).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync(ex.Message).ConfigureAwait(false);
            return 1;
        }
    }

    private static async Task<int> RunExtractAsync(IReadOnlyList<string> args)
    {
        string? password = null;
        for (var i = 4; i < args.Count; i++)
        {
            if (args[i] == PasswordFlag && i + 1 < args.Count) password = args[++i];
            else
            {
                await Console.Error.WriteLineAsync("Invalid extract arguments.").ConfigureAwait(false);
                return 2;
            }
        }
        try
        {
            Directory.CreateDirectory(args[3]);
            var path = ArchiveReader.ExtractEntry(args[1], args[2], password, args[3]);
            await Console.Out.WriteLineAsync(path).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync(ex.Message).ConfigureAwait(false);
            return 1;
        }
    }
}
