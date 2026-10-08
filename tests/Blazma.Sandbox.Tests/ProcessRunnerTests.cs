using Blazma.Sandbox.Processes;

namespace Blazma.Sandbox.Tests;

/// <summary>Runs real child processes through /bin/sh; skipped on Windows, where CI does not run tests.</summary>
public sealed class ProcessRunnerTests : IDisposable
{
    private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory("blz-proc");

    public void Dispose() => _dir.Delete(recursive: true);

    private static ProcessRequest Sh(string script, params string[] args) => new("/bin/sh", ["-c", script, "sh", .. args]);

    [Fact]
    public async Task Arguments_stay_single_arguments_and_exit_codes_are_returned()
    {
        if (OperatingSystem.IsWindows()) return;
        var result = await ProcessRunner.Instance.RunAsync(Sh("printf '%s|' \"$@\"; exit 3", "a b", "c\"d", "'; rm -rf /", "$(id)"), CancellationToken.None);
        Assert.Equal(3, result.ExitCode);
        Assert.False(result.Succeeded);
        Assert.Equal("a b|c\"d|'; rm -rf /|$(id)|", result.StandardOutput);
    }

    [Fact]
    public async Task Standard_input_is_delivered_and_closed()
    {
        if (OperatingSystem.IsWindows()) return;
        var result = await ProcessRunner.Instance.RunAsync(Sh("cat; echo err >&2") with { StandardInput = "secret-on-stdin" }, CancellationToken.None);
        Assert.True(result.Succeeded);
        Assert.Equal("secret-on-stdin", result.StandardOutput);
        Assert.Equal("err", result.StandardError.Trim());
    }

    [Fact]
    public async Task Output_is_capped_but_drained()
    {
        if (OperatingSystem.IsWindows()) return;
        var result = await ProcessRunner.Instance.RunAsync(Sh("head -c 300000 /dev/zero | tr '\\0' 'x'") with { MaxOutputChars = 1000 }, CancellationToken.None);
        Assert.True(result.Succeeded);
        Assert.Equal(1000, result.StandardOutput.Length);
        Assert.True(result.OutputTruncated);
    }

    [Fact]
    public async Task A_timeout_kills_the_process_and_is_reported()
    {
        if (OperatingSystem.IsWindows()) return;
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var result = await ProcessRunner.Instance.RunAsync(Sh("sleep 30") with { Timeout = TimeSpan.FromMilliseconds(300) }, CancellationToken.None);
        Assert.True(result.TimedOut);
        Assert.False(result.Succeeded);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(15));
    }

    [Fact]
    public async Task Cancellation_kills_the_process_and_throws()
    {
        if (OperatingSystem.IsWindows()) return;
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var watch = System.Diagnostics.Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ProcessRunner.Instance.RunAsync(Sh("sleep 30"), cts.Token));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(15));
    }

    [Fact]
    public async Task A_missing_program_throws()
    {
        await Assert.ThrowsAnyAsync<Exception>(() => ProcessRunner.Instance.RunAsync(new ProcessRequest(Path.Combine(_dir.FullName, "missing-program"), []), CancellationToken.None));
    }

    [Fact]
    public void Request_text_never_contains_standard_input()
    {
        var request = new ProcessRequest("powershell.exe", ["-Command", "-"]) { StandardInput = "P@ssw0rd" };
        Assert.DoesNotContain("P@ssw0rd", request.ToString());
    }

    [Fact]
    public void Secret_files_are_private_and_removed_on_dispose()
    {
        string path;
        using (var secret = SecretFile.Create(_dir.FullName, "P@ss wörd"))
        {
            path = secret.Path;
            Assert.Equal("P@ss wörd"u8.ToArray(), File.ReadAllBytes(path));
            if (!OperatingSystem.IsWindows())
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
        }
        Assert.False(File.Exists(path));
    }
}
