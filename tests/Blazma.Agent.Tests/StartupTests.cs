using System.ComponentModel;
using System.Text;
using Blazma.Contracts;

namespace Blazma.Agent.Tests;

/// <summary>How the agent starts the sample, its diagnostic log and its heartbeat: the parts of startup that do not need Windows.</summary>
public sealed class StartupTests : IDisposable
{
    private const string System32 = @"C:\Windows\System32";
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "blazma-agent-tests-" + Guid.NewGuid().ToString("N"));

    public StartupTests() => Directory.CreateDirectory(_folder);

    public void Dispose()
    {
        AgentLog.Use(null);
        try { Directory.Delete(_folder, recursive: true); } catch (IOException) { }
    }

    /// <summary>MZ header pointing at a PE header with the given COFF characteristics.</summary>
    private static byte[] Pe(ushort characteristics)
    {
        var bytes = new byte[512];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(bytes, 0x3C);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(0x80));
        BitConverter.GetBytes(characteristics).CopyTo(bytes, 0x80 + 22);
        return bytes;
    }

    private static readonly byte[] Program = Pe(0x0102);
    private static readonly byte[] Library = Pe(0x2102);
    private static readonly byte[] Text = Encoding.ASCII.GetBytes("echo hello\r\n");

    [Fact]
    public void Pe_headers_are_told_apart()
    {
        Assert.Equal(PeKind.Program, SampleLauncher.Inspect(Program));
        Assert.Equal(PeKind.Library, SampleLauncher.Inspect(Library));
        Assert.Equal(PeKind.None, SampleLauncher.Inspect(Text));
        Assert.Equal(PeKind.None, SampleLauncher.Inspect([]));
        Assert.Equal(PeKind.Program, SampleLauncher.Inspect(Program.AsSpan(0, 0x40))); // PE header not read: MZ is enough
    }

    [Fact]
    public void Programs_and_documents_open_through_the_shell_like_a_double_click()
    {
        var exe = SampleLauncher.Plan(@"C:\Users\WDAGUtilityAccount\Desktop\setup.exe", Program, System32);
        Assert.Equal(@"C:\Users\WDAGUtilityAccount\Desktop\setup.exe", exe.FileName);
        Assert.Equal(string.Empty, exe.Arguments);
        Assert.True(exe.UseShellExecute); // own console window, not the agent's

        foreach (var name in new[] { "invoice.pdf", "page.hta", "link.lnk", "panel.cpl", "readme.docx", "noextension" })
        {
            var plan = SampleLauncher.Plan($@"C:\d\{name}", name == "panel.cpl" ? Library : Text, System32);
            Assert.Equal($@"C:\d\{name}", plan.FileName);
            Assert.True(plan.UseShellExecute, name);
        }
    }

    [Fact]
    public void A_program_with_another_extension_is_started_directly()
    {
        // The shell would only ask which app should open a ".bin" file.
        var plan = SampleLauncher.Plan(@"C:\d\payload.bin", Program, System32);
        Assert.Equal(@"C:\d\payload.bin", plan.FileName);
        Assert.False(plan.UseShellExecute);
    }

    [Theory]
    [InlineData(@"C:\d\x.dll", "rundll32.exe", "\"C:\\d\\x.dll\",#1")]
    [InlineData(@"C:\d\x.bin", "rundll32.exe", "\"C:\\d\\x.bin\",#1")] // a DLL under another name
    [InlineData(@"C:\d\x.msi", "msiexec.exe", "/i \"C:\\d\\x.msi\" /qn")]
    [InlineData(@"C:\d\x.ps1", @"WindowsPowerShell\v1.0\powershell.exe", "-NoProfile -ExecutionPolicy Bypass -File \"C:\\d\\x.ps1\"")]
    [InlineData(@"C:\d\my file (1).bat", "cmd.exe", "/c \"\"C:\\d\\my file (1).bat\"\"")]
    [InlineData(@"C:\d\x.CMD", "cmd.exe", "/c \"\"C:\\d\\x.CMD\"\"")]
    [InlineData(@"C:\d\x.vbs", "wscript.exe", "\"C:\\d\\x.vbs\"")]
    [InlineData(@"C:\d\x.js", "wscript.exe", "\"C:\\d\\x.js\"")]
    public void Scripts_installers_and_libraries_use_their_host(string path, string host, string arguments)
    {
        var plan = SampleLauncher.Plan(path, path.EndsWith(".bin", StringComparison.Ordinal) || path.EndsWith(".dll", StringComparison.Ordinal) ? Library : Text, System32);
        Assert.Equal(Path.Combine(System32, host), plan.FileName);
        Assert.Equal(arguments, plan.Arguments);
        Assert.True(plan.UseShellExecute);
    }

    [Fact]
    public void Start_failures_are_explained()
    {
        Assert.Contains("Microsoft Defender", SampleLauncher.DescribeFailure(new Win32Exception(225)));
        Assert.Contains("Microsoft Defender", SampleLauncher.DescribeFailure(new IOException("Operation did not complete successfully because the file contains a virus.", unchecked((int)0x800700E1))));
        Assert.Contains("Microsoft Defender", SampleLauncher.DescribeFailure(new InvalidOperationException("x", new Win32Exception(226))));
        Assert.Contains("may have been removed", SampleLauncher.DescribeFailure(new FileNotFoundException("Could not find file 'C:\\d\\x.exe'.")));
        Assert.Equal("The sample could not be started: The specified executable is not a valid application for this OS platform.",
            SampleLauncher.DescribeFailure(new Win32Exception(193, "The specified executable is not a valid application for this OS platform.")));
    }

    [Fact]
    public void Log_lines_are_appended_with_timestamps_and_readable_while_open()
    {
        var path = Path.Combine(_folder, Protocol.AgentLogFile);
        File.WriteAllText(path, "earlier run\n");
        using (var log = new AgentLog(path))
        {
            AgentLog.Use(log);
            AgentLog.Info("starting");
            AgentLog.Error("component failed", new InvalidOperationException("boom"));

            // The host reads it while the agent still has it open.
            using var reader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var text = new StreamReader(reader, Encoding.UTF8).ReadToEnd();
            Assert.StartsWith("earlier run\n", text, StringComparison.Ordinal);
            Assert.Matches(@"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}Z INFO \[\d+\] starting", text);
            Assert.Contains("ERROR", text, StringComparison.Ordinal);
            Assert.Contains("System.InvalidOperationException: boom", text, StringComparison.Ordinal);
        }
        AgentLog.Info("after dispose is ignored");
        Assert.DoesNotContain("after dispose", File.ReadAllText(path), StringComparison.Ordinal);
    }

    [Fact]
    public void Log_stops_at_its_size_limit()
    {
        var path = Path.Combine(_folder, "capped.log");
        using (var log = new AgentLog(path, maxBytes: 4096))
        {
            for (var i = 0; i < 500; i++) log.Write("INFO", "line " + i + new string('x', 40), null);
        }
        var length = new FileInfo(path).Length;
        Assert.True(length <= 4096, $"{length} bytes");
        Assert.Contains("size limit", File.ReadAllText(path), StringComparison.Ordinal);
    }

    [Fact]
    public void Repeated_failures_are_logged_a_few_times_only()
    {
        var path = Path.Combine(_folder, "limited.log");
        using (var log = new AgentLog(path))
        {
            for (var i = 0; i < 50; i++) log.WriteLimited("screenshot", "A screenshot failed", null);
        }
        Assert.Equal(3, File.ReadAllLines(path).Count(l => l.Contains("A screenshot failed", StringComparison.Ordinal)));
    }

    [Fact]
    public void A_log_that_cannot_be_opened_never_throws()
    {
        using var log = new AgentLog(Path.Combine(_folder, "missing-folder", "agent.log"));
        log.Write("INFO", "nothing happens", null);
    }

    [Fact]
    public void Heartbeats_keep_coming_when_a_beat_fails()
    {
        var beats = 0;
        using var done = new ManualResetEventSlim();
        using (new Heartbeat(() =>
               {
                   if (Interlocked.Increment(ref beats) >= 4) done.Set();
                   throw new UnauthorizedAccessException("heartbeat.json is locked");
               }, TimeSpan.FromMilliseconds(20)))
        {
            Assert.True(done.Wait(TimeSpan.FromSeconds(10)));
        }
        var afterStop = Volatile.Read(ref beats);
        Thread.Sleep(100);
        Assert.Equal(afterStop, Volatile.Read(ref beats));
    }
}
