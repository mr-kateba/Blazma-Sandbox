using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Blazma.Sandbox.Processes;
using Microsoft.Extensions.Logging;

namespace Blazma.Sandbox.Providers.WindowsSandbox;

/// <summary>What the Windows Sandbox session needs from the host computer. Replaced by a fake in tests.</summary>
internal interface IWindowsSandboxHost
{
    /// <summary><c>WindowsSandbox.exe</c>, or null when Windows Sandbox is not installed (or this is not Windows).</summary>
    string? SandboxExecutable { get; }

    /// <summary><c>wsb.exe</c>, the command line of Windows Sandbox from the Microsoft Store (Windows 11 24H2 and later), or null.</summary>
    string? WsbExecutable { get; }

    /// <summary>Starts a program without waiting for it. <paramref name="exited"/> receives its exit code when it ends.</summary>
    void Launch(string fileName, IReadOnlyList<string> arguments, Action<int>? exited = null);

    /// <summary>Names of the Windows Sandbox window processes running now; any of them means a sandbox is open.</summary>
    IReadOnlyList<string> RunningClients();

    /// <summary>Ends every Windows Sandbox process. The last resort when <c>wsb stop</c> is unavailable or failed.</summary>
    void KillAll(ILogger logger);
}

internal sealed class WindowsSandboxHost : IWindowsSandboxHost
{
    public static WindowsSandboxHost Instance { get; } = new();

    /// <summary>
    /// The windows. Before 24H2 the window is WindowsSandboxClient; from 24H2 it is WindowsSandboxRemoteSession.
    /// WindowsSandbox.exe itself is only a launcher there and may exit at once.
    /// </summary>
    internal static readonly string[] ClientProcessNames = ["WindowsSandbox", "WindowsSandboxClient", "WindowsSandboxRemoteSession"];

    /// <summary>The per-user server (24H2 and later) can outlive the sandbox, so it never counts as "a sandbox is open".</summary>
    internal static readonly string[] AllProcessNames = [.. ClientProcessNames, "WindowsSandboxServer"];

    public string? SandboxExecutable => Find("WindowsSandbox.exe");
    public string? WsbExecutable => Find("wsb.exe");

    /// <summary>System32 first, then the Store app's execution alias. Never the PATH or the current folder.</summary>
    private static string? Find(string name)
    {
        if (!OperatingSystem.IsWindows()) return null;
        string[] candidates =
        [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), name),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", name),
        ];
        return candidates.FirstOrDefault(c => Path.IsPathFullyQualified(c) && File.Exists(c));
    }

    public void Launch(string fileName, IReadOnlyList<string> arguments, Action<int>? exited = null)
    {
        var psi = new ProcessStartInfo(fileName) { UseShellExecute = false, CreateNoWindow = false };
        foreach (var argument in arguments) psi.ArgumentList.Add(argument);
        var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        process.Exited += (_, _) =>
        {
            try { exited?.Invoke(process.ExitCode); }
            catch (InvalidOperationException) { }
            finally { process.Dispose(); }
        };
        if (!process.Start())
        {
            process.Dispose();
            throw new InvalidOperationException($"{Path.GetFileName(fileName)} did not start.");
        }
    }

    public IReadOnlyList<string> RunningClients() => ClientProcessNames.Where(IsRunning).ToList();

    private static bool IsRunning(string name)
    {
        var processes = Process.GetProcessesByName(name);
        foreach (var p in processes) p.Dispose();
        return processes.Length > 0;
    }

    public void KillAll(ILogger logger)
    {
        foreach (var name in AllProcessNames)
        {
            foreach (var p in Process.GetProcessesByName(name))
            {
                try { p.Kill(entireProcessTree: true); }
                catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException) { logger.LogDebug(ex, "Could not stop {Process}", name); }
                finally { p.Dispose(); }
            }
        }
    }
}

/// <summary>
/// The parts of <c>wsb.exe</c> Blazma uses (<c>list</c>, <c>stop</c>, <c>exec</c>). Output is read
/// defensively: the command is a preview and its format is not documented, so sandbox ids are
/// recognised by their GUID shape, in plain text or JSON, and entries marked as stopped are skipped.
/// </summary>
internal sealed partial class WsbCli(IProcessRunner runner, string executable)
{
    public static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(60);

    /// <summary>Ids of the running sandboxes, or null when the command failed (state unknown).</summary>
    public async Task<IReadOnlyList<string>?> ListAsync(CancellationToken cancellationToken)
    {
        var result = await RunAsync(["list"], cancellationToken).ConfigureAwait(false);
        return result.Succeeded ? ParseRunningIds(result.StandardOutput) : null;
    }

    public async Task<ProcessResult> StopAsync(string id, CancellationToken cancellationToken) =>
        await RunAsync(["stop", "--id", id], cancellationToken).ConfigureAwait(false);

    /// <summary>Runs <paramref name="command"/> in the signed-in user's session inside the sandbox.</summary>
    public async Task<ProcessResult> ExecAsync(string id, string command, CancellationToken cancellationToken) =>
        await RunAsync(["exec", "--id", id, "-c", command, "-r", "ExistingLogin"], cancellationToken).ConfigureAwait(false);

    /// <summary>A wsb.exe that cannot be started is a failed command, never an exception: the session then works without it.</summary>
    private async Task<ProcessResult> RunAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        try
        {
            return await runner.RunAsync(new ProcessRequest(executable, arguments) { Timeout = CommandTimeout, MaxOutputChars = 256 * 1024 }, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new ProcessResult(-1, string.Empty, ex.Message);
        }
    }

    internal static IReadOnlyList<string> ParseRunningIds(string output)
    {
        var ids = new List<string>();
        var text = output.Trim();
        if (text.StartsWith('[') || text.StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(text);
                Walk(doc.RootElement, ids);
                return ids.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            }
            catch (JsonException) { ids.Clear(); }
        }
        foreach (var line in text.Split('\n'))
        {
            if (IsStopped(line)) continue;
            ids.AddRange(GuidRegex().Matches(line).Select(m => m.Value));
        }
        return ids.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static void Walk(JsonElement element, List<string> ids)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray()) Walk(item, ids);
                break;
            case JsonValueKind.Object:
                var stopped = element.EnumerateObject().Any(p => p.Value.ValueKind == JsonValueKind.String
                    && (p.Name.Contains("status", StringComparison.OrdinalIgnoreCase) || p.Name.Contains("state", StringComparison.OrdinalIgnoreCase))
                    && IsStopped(p.Value.GetString()!));
                if (stopped) return;
                foreach (var property in element.EnumerateObject()) Walk(property.Value, ids);
                break;
            case JsonValueKind.String:
                if (GuidRegex().Match(element.GetString()!) is { Success: true } m && m.Length == element.GetString()!.Trim().Length) ids.Add(m.Value);
                break;
        }
    }

    private static bool IsStopped(string text) => text.Contains("stopped", StringComparison.OrdinalIgnoreCase);

    [GeneratedRegex(@"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", RegexOptions.CultureInvariant)]
    private static partial Regex GuidRegex();
}
