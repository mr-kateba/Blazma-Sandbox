using System.Text;
using Blazma.Sandbox.Processes;

namespace Blazma.Sandbox.Providers.VirtualMachine.HyperV;

/// <summary>What a script printed: success marker, error text and <c>key=value</c> lines.</summary>
internal sealed record PowerShellOutput(bool Ok, string? Error, IReadOnlyList<KeyValuePair<string, string>> Values, ProcessResult Process)
{
    public string? Get(string key) => Values.FirstOrDefault(v => v.Key == key).Value;
    public IEnumerable<string> All(string key) => Values.Where(v => v.Key == key).Select(v => v.Value);
    public string Describe() => Error ?? Process.Describe();
}

/// <summary>
/// Runs Windows PowerShell as <c>powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -</c>
/// with the whole script on standard input, so a password inside it never appears on a command line
/// or in the process list. Scripts print <c>BLAZMA-OK</c> when they finish and <c>BLAZMA-ERROR: …</c>
/// when they fail, so success does not depend on PowerShell's exit-code rules.
/// </summary>
internal sealed class PowerShellHost(IProcessRunner runner, string executable, TimeSpan timeout)
{
    public static readonly IReadOnlyList<string> Arguments = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"];
    public const string OkMarker = "BLAZMA-OK";
    public const string ErrorMarker = "BLAZMA-ERROR: ";

    public async Task<PowerShellOutput> RunAsync(string script, CancellationToken cancellationToken, TimeSpan? timeoutOverride = null)
    {
        var result = await runner.RunAsync(new ProcessRequest(executable, Arguments)
        {
            StandardInput = PowerShellText.Bootstrap(script),
            Timeout = timeoutOverride ?? timeout,
            MaxOutputChars = 4 * 1024 * 1024,
            OutputEncoding = Encoding.UTF8,
        }, cancellationToken).ConfigureAwait(false);
        return Parse(result);
    }

    public async Task<PowerShellOutput> RequireAsync(string script, string what, CancellationToken cancellationToken, TimeSpan? timeoutOverride = null)
    {
        var output = await RunAsync(script, cancellationToken, timeoutOverride).ConfigureAwait(false);
        if (!output.Ok) throw new InvalidOperationException($"Hyper-V could not {what} ({output.Describe()}).");
        return output;
    }

    public static PowerShellOutput Parse(ProcessResult result)
    {
        var ok = false;
        string? error = null;
        var values = new List<KeyValuePair<string, string>>();
        foreach (var raw in result.StandardOutput.Split('\n'))
        {
            var line = raw.Trim('\r', '﻿', ' ');
            if (line == OkMarker) ok = true;
            else if (line.StartsWith(ErrorMarker, StringComparison.Ordinal)) error = line[ErrorMarker.Length..];
            else if (line.IndexOf('=') is var at and > 0) values.Add(new(line[..at], line[(at + 1)..]));
        }
        return new PowerShellOutput(ok && error is null && !result.TimedOut, error, values, result);
    }
}
