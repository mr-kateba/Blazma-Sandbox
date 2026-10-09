using System.Diagnostics;
using System.Text.Json;
using Blazma.Core.Abstractions;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Static;

/// <summary>Options passed from the host to the static-analysis helper on its command line.</summary>
public sealed record StaticWorkerOptions(bool DetectCapabilities = true, string? YaraFolder = null);

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

    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(90);

    /// <summary>True when the process was started as the helper (see <see cref="RunAsync"/>).</summary>
    public static bool IsWorkerInvocation(IReadOnlyList<string> args) => args.Count >= 2 && args[0] == Flag;

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
        foreach (var arg in BuildArguments(path, options)) psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("The static analysis helper did not start.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Timeout);
        try
        {
            var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            if (process.ExitCode != 0) throw new InvalidOperationException((await stderr.ConfigureAwait(false)).Trim());
            return JsonSerializer.Deserialize<StaticReport>(await stdout.ConfigureAwait(false), json)
                ?? throw new InvalidDataException("Empty static report.");
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
        return args;
    }

    /// <summary>Parses the helper's arguments; null when they are not a valid helper invocation.</summary>
    public static (string Path, StaticWorkerOptions Options)? ParseArguments(IReadOnlyList<string> args)
    {
        if (!IsWorkerInvocation(args)) return null;
        var options = new StaticWorkerOptions();
        for (var i = 2; i < args.Count; i++)
        {
            switch (args[i])
            {
                case NoCapabilitiesFlag: options = options with { DetectCapabilities = false }; break;
                case YaraFlag when i + 1 < args.Count: options = options with { YaraFolder = args[++i] }; break;
                default: return null;
            }
        }
        return (args[1], options);
    }

    /// <summary>The helper's entry point: analyzes one file and writes the report as JSON to stdout.</summary>
    public static async Task<int> RunAsync(IReadOnlyList<string> args, JsonSerializerOptions json, Func<string, IYaraScanner?>? loadYara = null)
    {
        var parsed = ParseArguments(args);
        if (parsed is not { } p)
        {
            await Console.Error.WriteLineAsync("Invalid static worker arguments.").ConfigureAwait(false);
            return 2;
        }
        try
        {
            using var cts = new CancellationTokenSource(Timeout - TimeSpan.FromSeconds(10));
            var yara = p.Options.YaraFolder is { } folder && loadYara is not null ? loadYara(folder) : null;
            var report = await new StaticAnalyzer(yara, p.Options.DetectCapabilities).AnalyzeAsync(p.Path, cts.Token).ConfigureAwait(false);
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
}
