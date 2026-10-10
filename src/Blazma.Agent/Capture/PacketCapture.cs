using System.Diagnostics;
using Blazma.Contracts;

namespace Blazma.Agent.Capture;

/// <summary>
/// Records network traffic with pktmon, which ships with Windows 10 2004 and later, and
/// converts it to pcapng at the end. Only used when the real network is enabled.
/// </summary>
internal sealed class PacketCapture(EventSink sink, string workFolder, Action<string> note)
{
    private string Etl => Path.Combine(workFolder, "capture.etl");
    private string Pcap => Path.Combine(workFolder, "capture.pcapng");
    private bool _running;

    private static string Pktmon => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "pktmon.exe");

    public void Start()
    {
        if (!File.Exists(Pktmon)) { note("pktmon is not available in this Windows version; no network capture."); return; }
        Directory.CreateDirectory(workFolder);
        _running = Run("start", "--capture", "--pkt-size", "0", "--file-name", Etl) == 0;
        if (!_running) note("pktmon could not start; no network capture.");
    }

    public void StopAndSend()
    {
        if (!_running) return;
        _running = false;
        Run("stop");
        if (Run("etl2pcap", Etl, "--out", Pcap) != 0 || !File.Exists(Pcap)) { note("The network capture could not be converted."); return; }
        var info = new FileInfo(Pcap);
        if (info.Length > Protocol.Limits.MaxPcapBytes - 1024) { note("The network capture was too large to send."); return; }
        sink.WriteSigned(Protocol.PcapFile, File.ReadAllBytes(Pcap));
    }

    private static int Run(params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo(Pktmon) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var a in args) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi);
            if (p is null) return -1;
            // Read both pipes at once: reading them one after the other can deadlock, and a blocking
            // read would never reach the timeout below if pktmon hung.
            var output = p.StandardOutput.ReadToEndAsync();
            var error = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(60_000)) { p.Kill(true); AgentLog.Warn($"pktmon {string.Join(' ', args)} did not finish in time"); return -1; }
            if (p.ExitCode != 0) AgentLog.Warn($"pktmon {string.Join(' ', args)} exited with {p.ExitCode}: {Clip(output.Result)} {Clip(error.Result)}");
            return p.ExitCode;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException or AggregateException)
        {
            AgentLog.Warn($"pktmon {string.Join(' ', args)} could not run", ex);
            return -1;
        }
    }

    private static string Clip(string s) => s.Length > 500 ? s[..500] : s.Trim();
}
