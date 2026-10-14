using Blazma.Analysis.Engine;
using Blazma.Analysis.Static;
using Blazma.Core.Analysis;
using Blazma.Core.Events;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Tests;

/// <summary>Event kinds <see cref="Ev"/> has no shortcut for. Sequences start far above Ev's own so they never collide.</summary>
internal static class EvExtensions
{
    public static void RegKey(this Ev ev, int ms, int pid, ProcessKey? key, string name, string regKey) =>
        ev.Add(ms, EventAction.RegistryKeyCreate, pid, key, name, regKey, []);

    /// <summary>A task registration as the Task Scheduler reports it: from its own service process, with the name only.</summary>
    public static void Task(this Ev ev, int ms, int pid, ProcessKey? key, string name, string taskName) =>
        ev.Add(ms, EventAction.ScheduledTaskCreate, pid, key, name, @"\" + taskName, new() { [DetailKeys.TaskName] = taskName });

    public static void Add(this Ev ev, int ms, EventAction action, int pid, ProcessKey? key, string name, string? target, Dictionary<string, string> details) =>
        ev.Events.Add(new AnalysisEvent
        {
            Sequence = 1_000_000 + ev.Events.Count,
            Timestamp = new DateTimeOffset(2026, 10, 1, 12, 0, 0, TimeSpan.Zero).AddMilliseconds(ms),
            RelativeTime = TimeSpan.FromMilliseconds(ms),
            Category = action.DefaultCategory(),
            Action = action,
            ProcessId = pid,
            Process = key,
            ProcessName = name,
            Target = target,
            Details = details,
            Source = "test",
        });
}

/// <summary>
/// Hand-written event sequences shaped like real runs in Windows Sandbox: what common installer
/// technologies do, what Windows does on its own in the background, and what droppers do. No
/// real software or malware is involved; names and addresses are made up or documentation ranges.
/// </summary>
internal static class Scenarios
{
    public const string User = @"C:\Users\WDAGUtilityAccount";
    public const string Desktop = User + @"\Desktop";
    public const string Temp = User + @"\AppData\Local\Temp";
    public const string Local = User + @"\AppData\Local";
    public const string Roaming = User + @"\AppData\Roaming";

    /// <summary>The agent copies the sample to the desktop and starts it; its process id is the parent.</summary>
    public const int Agent = 3000;

    public sealed record Scenario(string Name, IReadOnlyList<AnalysisEvent> Events, StaticReport Static)
    {
        public AnalysisResult Run(EngineSettings? settings = null) => TestEngine.Run(Events, settings, Static);
    }

    public static StaticReport Static(string fileName, SignatureStatus signature = SignatureStatus.NotSigned, string? publisher = null,
        Dictionary<string, string>? version = null, string[]? sections = null, IReadOnlyList<Capability>? capabilities = null, FileKind kind = FileKind.Executable)
    {
        var sample = TestEngine.Sample(fileName) with { Kind = kind };
        return new StaticReport
        {
            Sample = sample,
            Pe = kind == FileKind.Msi ? null : new PeInfo
            {
                Machine = "x86", Is64Bit = false, IsDll = false, Subsystem = "WindowsGui", IsDotNet = false,
                VersionInfo = version ?? [],
                Sections = (sections ?? [".text", ".rdata", ".data", ".rsrc"]).Select(s => new PeSection(s, 4096, 4096, 5.9, s == ".text", s == ".data")).ToList(),
                Imports = [new PeImport("KERNEL32.dll", ["CreateFileW", "WriteFile", "CreateProcessW", "GetProcAddress"])],
            },
            Signature = new SignatureInfo(signature, publisher),
            Capabilities = capabilities ?? [],
        };
    }

    // ---- Clean installers --------------------------------------------------------------------

    /// <summary>
    /// A per-user Inno Setup installer of a code editor, signed: the loader unpacks its setup engine
    /// (is-XXXXX.tmp\setup.tmp), installs under AppData\Local\Programs, registers file types,
    /// creates shortcuts, then starts the editor, which checks for updates.
    /// </summary>
    public static Scenario InnoSetupSigned()
    {
        const string name = "EditorUserSetup-x64-1.95.3.exe";
        var ev = new Ev();
        var s = ev.Start(0, 4100, Agent, name, $@"{Desktop}\{name}", $"\"{Desktop}\\{name}\"", sample: true);
        var engineImage = $@"{Temp}\is-8R0FQ.tmp\EditorUserSetup-x64-1.95.3.tmp";
        ev.File(150, 4100, s, name, EventAction.FileCreate, engineImage);
        var setup = ev.Start(400, 4200, 4100, "EditorUserSetup-x64-1.95.3.tmp", engineImage,
            $"\"{engineImage}\" /SL5=\"$4040C,87252360,1012736,{Desktop}\\{name}\"");
        ev.File(500, 4200, setup, "setup.tmp", EventAction.FileCreate, $@"{Temp}\is-3KQ7V.tmp\_isetup\_setup64.tmp");
        ev.File(510, 4200, setup, "setup.tmp", EventAction.FileCreate, $@"{Temp}\is-3KQ7V.tmp\_isetup\_iscrypt.dll");
        var app = $@"{Local}\Programs\Contoso Editor";
        foreach (var (ms, file) in new[] { (900, "Editor.exe"), (950, "ffmpeg.dll"), (980, "libEGL.dll"), (1000, @"bin\editor.cmd"), (1100, "unins000.exe"), (1120, "unins000.dat"), (1150, @"resources\app\package.json") })
            ev.File(ms, 4200, setup, "setup.tmp", EventAction.FileCreate, $@"{app}\{file}");
        ev.Reg(1300, 4200, setup, "setup.tmp", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1", "DisplayName", "Contoso Editor (User)");
        ev.Reg(1310, 4200, setup, "setup.tmp", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1", "UninstallString", $"\"{app}\\unins000.exe\"");
        ev.Reg(1400, 4200, setup, "setup.tmp", @"HKCU\Software\Classes\Applications\Editor.exe\shell\open\command", "", $"\"{app}\\Editor.exe\" \"%1\"");
        ev.Reg(1450, 4200, setup, "setup.tmp", @"HKCU\Environment", "Path", $@"{User}\AppData\Local\Microsoft\WindowsApps;{app}\bin");
        ev.File(1500, 4200, setup, "setup.tmp", EventAction.FileCreate, $@"{Roaming}\Microsoft\Windows\Start Menu\Programs\Contoso Editor\Contoso Editor.lnk");
        var editor = ev.Start(9000, 4800, 4200, "Editor.exe", $@"{app}\Editor.exe", $"\"{app}\\Editor.exe\"");
        ev.Start(9300, 4810, 4800, "Editor.exe", $@"{app}\Editor.exe", $"\"{app}\\Editor.exe\" --type=gpu-process --gpu-preferences=UAAAAAAAAADgAAAYAAAAAAAAAAAAAAAAAABgAAAAAAAwAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAA");
        var git = ev.Start(9800, 4900, 4800, "cmd.exe", @"C:\Windows\System32\cmd.exe", "C:\\Windows\\system32\\cmd.exe /d /s /c \"git --version\"");
        ev.Exit(9900, 4900, git, "cmd.exe");
        ev.Dns(10000, 4800, editor, "Editor.exe", "update.editor.contoso.example", "13.107.246.40");
        ev.Connect(10100, 4800, editor, "Editor.exe", "13.107.246.40", 443);
        ev.Exit(11000, 4200, setup, "setup.tmp");
        ev.Exit(11100, 4100, s, name);
        return new Scenario("Inno Setup, signed, per-user", ev.Events, Static(name, SignatureStatus.Valid, "Contoso Corporation",
            version: new() { ["CompanyName"] = "Contoso Corporation", ["FileDescription"] = "Contoso Editor Setup", ["Comments"] = "This installation was built with Inno Setup." }));
    }

    /// <summary>
    /// An unsigned NSIS installer of an open-source editor into Program Files: plugin DLLs in its
    /// %TEMP%\nsXXXX.tmp folder, files, uninstall entry, shell menu entry, shortcuts, and nsExec
    /// running the installed program once through cmd /c to register file associations.
    /// </summary>
    public static Scenario NsisUnsigned()
    {
        const string name = "FabrikamEditor-2.4-setup.exe";
        var ev = new Ev();
        var s = ev.Start(0, 4300, Agent, name, $@"{Desktop}\{name}", $"\"{Desktop}\\{name}\"", sample: true);
        foreach (var (ms, plugin) in new[] { (100, "System.dll"), (110, "nsDialogs.dll"), (120, "StartMenu.dll"), (130, "nsExec.dll") })
            ev.File(ms, 4300, s, name, EventAction.FileCreate, $@"{Temp}\nsq3A1F.tmp\{plugin}");
        const string app = @"C:\Program Files\Fabrikam Editor";
        foreach (var (ms, file) in new[] { (600, "editor.exe"), (650, "SciLexer.dll"), (700, @"plugins\Config\plugins.xml"), (760, "uninstall.exe"), (780, "readme.txt") })
            ev.File(ms, 4300, s, name, EventAction.FileCreate, $@"{app}\{file}");
        ev.Reg(900, 4300, s, name, @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Fabrikam Editor", "UninstallString", $"\"{app}\\uninstall.exe\"");
        ev.Reg(950, 4300, s, name, @"HKLM\SOFTWARE\Classes\*\shell\Edit with Fabrikam Editor\command", "", $"\"{app}\\editor.exe\" \"%1\"");
        ev.File(1000, 4300, s, name, EventAction.FileCreate, @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Fabrikam Editor\Fabrikam Editor.lnk");
        ev.File(1010, 4300, s, name, EventAction.FileCreate, @"C:\Users\Public\Desktop\Fabrikam Editor.lnk");
        var cmd = ev.Start(1200, 4400, 4300, "cmd.exe", @"C:\Windows\System32\cmd.exe", $"\"C:\\Windows\\system32\\cmd.exe\" /c \"\"{app}\\editor.exe\" --register-associations\"");
        var reg = ev.Start(1300, 4410, 4400, "editor.exe", $@"{app}\editor.exe", $"\"{app}\\editor.exe\" --register-associations");
        ev.Reg(1400, 4410, reg, "editor.exe", @"HKLM\SOFTWARE\Classes\.fed", "", "FabrikamEditor.Document");
        ev.Exit(1500, 4410, reg, "editor.exe");
        ev.Exit(1510, 4400, cmd, "cmd.exe");
        ev.File(1600, 4300, s, name, EventAction.FileDelete, $@"{Temp}\nsq3A1F.tmp\System.dll");
        ev.Exit(2000, 4300, s, name);
        var caps = CapabilityDetector.Detect([], ["Nullsoft.NSIS.exehead", "NullsoftInst", "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"]);
        return new Scenario("NSIS, unsigned, Program Files", ev.Events, Static(name, capabilities: caps));
    }

    /// <summary>
    /// An MSI package (WiX) installing an agent with a service and a startup entry, all under Program
    /// Files. The work is done by the Windows Installer service (msiexec /V, started by services.exe)
    /// and its custom-action server, not by the msiexec the agent started; the service then starts.
    /// </summary>
    public static Scenario MsiWithService(bool serviceGoesOnline = true)
    {
        const string name = "ContosoAgent-3.2.msi";
        var ev = new Ev();
        var s = ev.Start(0, 5000, Agent, "msiexec.exe", @"C:\Windows\System32\msiexec.exe", $"\"C:\\Windows\\System32\\msiexec.exe\" /i \"{Desktop}\\{name}\" /qn", sample: true);
        var svc = ev.Start(300, 5100, 640, "msiexec.exe", @"C:\Windows\System32\msiexec.exe", @"C:\Windows\system32\msiexec.exe /V");
        var ca = ev.Start(900, 5200, 5100, "msiexec.exe", @"C:\Windows\SysWOW64\msiexec.exe", @"C:\Windows\syswow64\MsiExec.exe -Embedding 6A9F1C2E0B3D4E5F8A7B6C5D4E3F2A1B C");
        ev.File(950, 5200, ca, "msiexec.exe", EventAction.FileCreate, @"C:\Windows\Installer\MSI8F21.tmp");
        ev.File(1000, 5100, svc, "msiexec.exe", EventAction.FileCreate, @"C:\Windows\Installer\4f1a2b.msi");
        ev.File(1010, 5100, svc, "msiexec.exe", EventAction.FileCreate, @"C:\Config.Msi\3c1d.rbs");
        const string app = @"C:\Program Files\Contoso\Agent";
        foreach (var (ms, file) in new[] { (1100, "ContosoAgent.exe"), (1150, "ContosoAgentSvc.exe"), (1200, "Contoso.Core.dll") })
            ev.File(ms, 5100, svc, "msiexec.exe", EventAction.FileCreate, $@"{app}\{file}");
        ev.Reg(1300, 5100, svc, "msiexec.exe", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{0B6C3A0E-6F7B-4C1D-9E5A-2D8F1B7C4A90}", "DisplayName", "Contoso Agent");
        ev.Reg(1350, 640, null, "services.exe", @"HKLM\System\CurrentControlSet\Services\ContosoAgentSvc", "ImagePath", $"\"{app}\\ContosoAgentSvc.exe\"");
        ev.Reg(1400, 5100, svc, "msiexec.exe", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "ContosoAgent", $"\"{app}\\ContosoAgent.exe\" /tray");
        ev.File(1450, 5100, svc, "msiexec.exe", EventAction.FileCreate, @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Contoso Agent.lnk");
        var agentSvc = ev.Start(4000, 5400, 640, "ContosoAgentSvc.exe", $@"{app}\ContosoAgentSvc.exe", $"\"{app}\\ContosoAgentSvc.exe\"");
        if (serviceGoesOnline)
        {
            ev.Dns(4500, 5400, agentSvc, "ContosoAgentSvc.exe", "updates.contoso.example", "198.51.100.20");
            ev.Connect(4600, 5400, agentSvc, "ContosoAgentSvc.exe", "198.51.100.20", 443);
        }
        ev.Exit(5000, 5000, s, "msiexec.exe");
        return new Scenario("MSI with a service", ev.Events, Static(name, kind: FileKind.Msi));
    }

    /// <summary>
    /// A signed Squirrel (Electron) installer: Setup.exe unpacks Update.exe to SquirrelTemp, which
    /// installs per user under AppData\Local, creates shortcuts, and starts the app, which adds itself
    /// to startup through Update.exe and contacts its service.
    /// </summary>
    public static Scenario SquirrelSigned()
    {
        const string name = "NorthwindChatSetup.exe";
        var ev = new Ev();
        var s = ev.Start(0, 6000, Agent, name, $@"{Desktop}\{name}", $"\"{Desktop}\\{name}\"", sample: true);
        ev.File(200, 6000, s, name, EventAction.FileCreate, $@"{Local}\SquirrelTemp\Update.exe");
        var upd = ev.Start(400, 6100, 6000, "Update.exe", $@"{Local}\SquirrelTemp\Update.exe", $"\"{Local}\\SquirrelTemp\\Update.exe\" --install . --rerunningWithoutUAC");
        const string root = Local + @"\NorthwindChat";
        foreach (var (ms, file) in new[] { (800, "Update.exe"), (900, @"app-1.4.2\NorthwindChat.exe"), (950, @"app-1.4.2\resources\app.asar"), (1000, @"packages\RELEASES") })
            ev.File(ms, 6100, upd, "Update.exe", EventAction.FileCreate, $@"{root}\{file}");
        ev.Reg(1100, 6100, upd, "Update.exe", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\NorthwindChat", "UninstallString", $"\"{root}\\Update.exe\" --uninstall");
        ev.File(1200, 6100, upd, "Update.exe", EventAction.FileCreate, $@"{Roaming}\Microsoft\Windows\Start Menu\Programs\Northwind Traders\Northwind Chat.lnk");
        ev.File(1210, 6100, upd, "Update.exe", EventAction.FileCreate, $@"{Desktop}\Northwind Chat.lnk");
        var install = ev.Start(1500, 6200, 6100, "NorthwindChat.exe", $@"{root}\app-1.4.2\NorthwindChat.exe", $"\"{root}\\app-1.4.2\\NorthwindChat.exe\" --squirrel-install 1.4.2");
        ev.Exit(2500, 6200, install, "NorthwindChat.exe");
        var app = ev.Start(3000, 6300, 6100, "NorthwindChat.exe", $@"{root}\app-1.4.2\NorthwindChat.exe", $"\"{root}\\app-1.4.2\\NorthwindChat.exe\" --squirrel-firstrun");
        ev.Reg(3500, 6300, app, "NorthwindChat.exe", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "com.northwind.chat",
            $"\"{root}\\Update.exe\" --processStart \"NorthwindChat.exe\" --process-start-args \"--start-minimized\"");
        ev.Dns(4000, 6300, app, "NorthwindChat.exe", "api.chat.northwind.example", "203.0.113.80");
        ev.Connect(4100, 6300, app, "NorthwindChat.exe", "203.0.113.80", 443);
        ev.Exit(4200, 6100, upd, "Update.exe");
        ev.Exit(4300, 6000, s, name);
        return new Scenario("Squirrel, signed", ev.Events, Static(name, SignatureStatus.Valid, "Northwind Traders Ltd",
            version: new() { ["CompanyName"] = "Northwind Traders Ltd", ["FileDescription"] = "Northwind Chat" }));
    }

    /// <summary>
    /// A signed web installer of a browser-style product: a bootstrapper in %TEMP% installs an
    /// updater under Program Files, which registers a service (through services.exe) and an hourly
    /// update task with schtasks (registered by the Task Scheduler service), and downloads the product.
    /// </summary>
    public static Scenario SignedUpdaterInstaller()
    {
        const string name = "ProductSetup.exe";
        var ev = new Ev();
        var s = ev.Start(0, 7000, Agent, name, $@"{Desktop}\{name}", $"\"{Desktop}\\{name}\"", sample: true);
        var boot = $@"{Temp}\GUM8F3A.tmp\ProductUpdateSetup.exe";
        ev.File(100, 7000, s, name, EventAction.FileCreate, boot);
        var b = ev.Start(300, 7100, 7000, "ProductUpdateSetup.exe", boot, $"\"{boot}\" /silent /install \"appguid={{8A69D345-D564-463C-AFF1-A69D9E530F96}}\"");
        const string upd = @"C:\Program Files (x86)\Woodgrove\Update";
        ev.File(600, 7100, b, "ProductUpdateSetup.exe", EventAction.FileCreate, $@"{upd}\WoodgroveUpdate.exe");
        ev.File(650, 7100, b, "ProductUpdateSetup.exe", EventAction.FileCreate, $@"{upd}\1.3.36.372\psmachine.dll");
        ev.Reg(800, 640, null, "services.exe", @"HKLM\System\CurrentControlSet\Services\wupdate", "ImagePath", $"\"{upd}\\WoodgroveUpdate.exe\" /svc");
        var u = ev.Start(1000, 7200, 7100, "WoodgroveUpdate.exe", $@"{upd}\WoodgroveUpdate.exe", $"\"{upd}\\WoodgroveUpdate.exe\" /install");
        var task = $"schtasks /create /tn \"WoodgroveUpdateTaskMachineUA\" /tr \"\\\"{upd}\\WoodgroveUpdate.exe\\\" /ua /installsource scheduler\" /sc hourly /ru SYSTEM /f";
        var st = ev.Start(1200, 7300, 7200, "schtasks.exe", @"C:\Windows\System32\schtasks.exe", task);
        ev.RegKey(1250, 1400, null, "svchost.exe", @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\WoodgroveUpdateTaskMachineUA");
        ev.Task(1260, 1400, null, "svchost.exe", "WoodgroveUpdateTaskMachineUA");
        ev.File(1270, 1400, null, "svchost.exe", EventAction.FileCreate, @"C:\Windows\System32\Tasks\WoodgroveUpdateTaskMachineUA");
        ev.Exit(1300, 7300, st, "schtasks.exe");
        ev.Dns(1500, 7200, u, "WoodgroveUpdate.exe", "dl.woodgrove.example", "198.51.100.44");
        ev.Connect(1600, 7200, u, "WoodgroveUpdate.exe", "198.51.100.44", 443);
        const string product = @"C:\Program Files\Woodgrove\Browser\Application";
        ev.File(3000, 7200, u, "WoodgroveUpdate.exe", EventAction.FileCreate, $@"{product}\woodgrove.exe");
        ev.Exit(5000, 7200, u, "WoodgroveUpdate.exe");
        ev.Exit(5100, 7100, b, "ProductUpdateSetup.exe");
        ev.Exit(5200, 7000, s, name);
        return new Scenario("Signed web installer with updater service and task", ev.Events, Static(name, SignatureStatus.Valid, "Woodgrove Bank Software"));
    }

    // ---- Windows Sandbox background ---------------------------------------------------------

    /// <summary>A portable console tool: writes its settings (in a folder named "update") and exits. Nothing else.</summary>
    public static Scenario QuietConsoleTool(bool withBackground)
    {
        const string name = "fabrikam-viewer.exe";
        var ev = new Ev();
        var s = ev.Start(0, 4800, Agent, name, $@"{Desktop}\{name}", $"\"{Desktop}\\{name}\"", sample: true);
        var console = ev.Start(30, 4810, 4800, "conhost.exe", @"C:\Windows\System32\conhost.exe", @"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1");
        ev.File(400, 4800, s, name, EventAction.FileCreate, $@"{Local}\FabrikamTools\update");
        ev.File(410, 4800, s, name, EventAction.FileCreate, $@"{Local}\FabrikamTools\update\viewer.ini");
        ev.Reg(500, 4800, s, name, @"HKCU\Software\FabrikamTools\Viewer", "WindowPlacement", "0,0,1024,768");
        ev.Reg(520, 4810, console, "conhost.exe", @"HKCU\Console\C:_Users_WDAGUtilityAccount_Desktop_fabrikam-viewer.exe", "WindowSize", "1966200");
        if (withBackground) AddSandboxBackground(ev);
        ev.Exit(8000, 4810, console, "conhost.exe");
        ev.Exit(8000, 4800, s, name);
        return new Scenario(withBackground ? "Quiet tool with sandbox background" : "Quiet tool", ev.Events, Static(name));
    }

    /// <summary>
    /// What a fresh Windows Sandbox does by itself while a sample runs: the agent's launcher and
    /// packet capture, Defender, Windows Update, Edge's updater (with its service and tasks),
    /// shell hosts, telemetry, licensing, and the Task Scheduler registering their tasks.
    /// </summary>
    public static void AddSandboxBackground(Ev ev)
    {
        // The agent's own launcher (before the sample) and its packet capture (started by the agent after the sample, so marked IsSample by it).
        var launcher = ev.Start(-9000, 2900, 2800, "cmd.exe", @"C:\Windows\System32\cmd.exe", @"C:\Windows\system32\cmd.exe /c C:\Users\WDAGUtilityAccount\Desktop\Blazma\blazma-agent.cmd");
        ev.File(-8000, 2900, launcher, "cmd.exe", EventAction.FileCreate, @"C:\Users\WDAGUtilityAccount\Desktop\Blazma\out\agent.log");
        var pktmon = ev.Start(9000, 3050, Agent, "pktmon.exe", @"C:\Windows\System32\PktMon.exe", @"C:\Windows\system32\pktmon.exe stop", sample: true);
        ev.File(9100, 3050, pktmon, "pktmon.exe", EventAction.FileCreate, $@"{Temp}\blazma-agent\PktMon.etl");
        ev.Reg(9150, 3050, pktmon, "pktmon.exe", @"HKLM\System\CurrentControlSet\Services\PktMon", "ImagePath", @"system32\drivers\PktMon.sys");

        // Defender.
        ev.File(200, 2100, null, "MsMpEng.exe", EventAction.FileWrite, @"C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache-5F2A.bin");
        ev.Reg(250, 2100, null, "MsMpEng.exe", @"HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates", "SignaturesLastUpdated", "01DB1A2B3C4D5E6F");
        ev.Reg(260, 2100, null, "MsMpEng.exe", @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", @"C:\ProgramData\Microsoft\Windows Defender", "0");
        var mpcmd = ev.Start(1000, 2300, 2100, "MpCmdRun.exe", @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MpCmdRun.exe",
            "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MpCmdRun.exe\" -wdenable");
        ev.Reg(1100, 2300, mpcmd, "MpCmdRun.exe", @"HKLM\System\CurrentControlSet\Services\WinDefend", "ImagePath",
            "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe\"");
        ev.Reg(1110, 2400, null, "NisSrv.exe", @"HKLM\System\CurrentControlSet\Services\WdNisSvc", "ImagePath",
            "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\NisSrv.exe\"");

        // Windows Update.
        var uso = ev.Start(1500, 2500, 1400, "MoUsoCoreWorker.exe", @"C:\Windows\System32\MoUsoCoreWorker.exe", @"C:\Windows\System32\mousocoreworker.exe -Embedding");
        ev.File(1600, 2500, uso, "MoUsoCoreWorker.exe", EventAction.FileWrite, @"C:\ProgramData\USOPrivate\UpdateStore\updatestore51b519d5-b6f5-4333-8df6-e74d7c9aa2d4.xml");
        ev.Dns(1650, 2500, uso, "MoUsoCoreWorker.exe", "fe3cr.delivery.mp.microsoft.com");
        ev.Connect(1660, 2500, uso, "MoUsoCoreWorker.exe", "20.12.23.50", 443);
        var wu = ev.Start(1700, 2510, 1400, "wuauclt.exe", @"C:\Windows\System32\wuauclt.exe", @"C:\Windows\system32\wuauclt.exe /RunHandlerComServer");
        ev.Reg(1710, 2510, wu, "wuauclt.exe", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "WuHandler", @"C:\Windows\system32\wuauclt.exe /RunHandlerComServer");
        ev.Start(1720, 2520, 1400, "usoclient.exe", @"C:\Windows\System32\usoclient.exe", "usoclient.exe StartScan");

        // Edge's updater: its service (registered through services.exe), its tasks and a download it runs.
        var edge = ev.Start(2000, 3500, 1400, "MicrosoftEdgeUpdate.exe", @"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
            "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /c");
        ev.Reg(2100, 700, null, "services.exe", @"HKLM\System\CurrentControlSet\Services\edgeupdate", "ImagePath",
            "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /svc");
        ev.Reg(2110, 3500, edge, "MicrosoftEdgeUpdate.exe", @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "MicrosoftEdgeAutoLaunch_0A1B2C",
            "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window --win-session-start");
        ev.RegKey(2200, 1400, null, "svchost.exe", @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineCore{A1B2C3D4-0000-1111-2222-333344445555}");
        ev.Task(2210, 1400, null, "svchost.exe", "MicrosoftEdgeUpdateTaskMachineCore{A1B2C3D4-0000-1111-2222-333344445555}");
        ev.File(2300, 3500, edge, "MicrosoftEdgeUpdate.exe", EventAction.FileCreate, @"C:\Program Files (x86)\Microsoft\EdgeUpdate\Download\{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}\130.0.2849.80\MicrosoftEdge_X64_130.0.2849.80.exe");
        var edgeSetup = ev.Start(2400, 3600, 3500, "MicrosoftEdge_X64_130.0.2849.80.exe",
            @"C:\Program Files (x86)\Microsoft\EdgeUpdate\Download\{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}\130.0.2849.80\MicrosoftEdge_X64_130.0.2849.80.exe", "MicrosoftEdge_X64_130.0.2849.80.exe --msedge --channel=stable --system-level --verbose-logging");
        ev.File(2500, 3600, edgeSetup, "MicrosoftEdge_X64_130.0.2849.80.exe", EventAction.FileCreate, $@"{Temp}\MicrosoftEdgeUpdate\setup.exe");
        ev.Dns(2600, 3500, edge, "MicrosoftEdgeUpdate.exe", "msedge.api.cdp.microsoft.com", "13.107.5.80");
        ev.Connect(2610, 3500, edge, "MicrosoftEdgeUpdate.exe", "13.107.5.80", 443);

        // Shell hosts, search, input, telemetry and licensing.
        foreach (var (pid, proc) in new[] { (3700, "SearchHost.exe"), (3710, "StartMenuExperienceHost.exe"), (3720, "RuntimeBroker.exe"), (3730, "ShellExperienceHost.exe"), (3740, "TextInputHost.exe") })
        {
            var k = ev.Start(3000 + pid - 3700, pid, 1200, proc, $@"C:\Windows\SystemApps\{proc}", proc);
            ev.File(3100 + pid - 3700, pid, k, proc, EventAction.FileWrite, $@"{Local}\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\{proc}.dat");
            ev.Reg(3150 + pid - 3700, pid, k, proc, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage2", "Favorites", "00");
        }
        var tel = ev.Start(4000, 3800, 1400, "CompatTelRunner.exe", @"C:\Windows\System32\CompatTelRunner.exe", "C:\\Windows\\system32\\compattelrunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun");
        var telConsole = ev.Start(4010, 3810, 3800, "conhost.exe", @"C:\Windows\System32\conhost.exe", @"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1");
        var telCmd = ev.Start(4020, 3820, 3800, "cmd.exe", @"C:\Windows\System32\cmd.exe", "C:\\Windows\\system32\\cmd.exe /d /c C:\\Windows\\system32\\compattelrunner.exe -m:invagent.dll");
        ev.File(4100, 3800, tel, "CompatTelRunner.exe", EventAction.FileWrite, @"C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl");
        ev.Exit(4200, 3820, telCmd, "cmd.exe");
        ev.Exit(4210, 3810, telConsole, "conhost.exe");
        var spp = ev.Start(4500, 3900, 640, "sppsvc.exe", @"C:\Windows\System32\sppsvc.exe", @"C:\Windows\system32\sppsvc.exe");
        ev.Reg(4600, 3900, spp, "sppsvc.exe", @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform", "ServiceSessionId", "1");
        ev.File(4700, 3900, spp, "sppsvc.exe", EventAction.FileWrite, @"C:\Windows\System32\spp\store\2.0\data.dat");
        var wmi = ev.Start(5000, 3950, 1300, "WmiPrvSE.exe", @"C:\Windows\System32\wbem\WmiPrvSE.exe", @"C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding");
        ev.File(5100, 3950, wmi, "WmiPrvSE.exe", EventAction.FileWrite, @"C:\Windows\System32\wbem\Repository\OBJECTS.DATA");
    }

    // ---- Malicious ----------------------------------------------------------------------------

    /// <summary>
    /// An unsigned dropper on the desktop: copies a payload with a Windows name into AppData, starts
    /// it, persists it under a bland name, runs hidden encoded PowerShell, contacts an IP address
    /// directly and deletes the original file.
    /// </summary>
    public static Scenario StealthyDropper(SignatureStatus signature = SignatureStatus.NotSigned, string? publisher = null)
    {
        const string name = "invoice_viewer.exe";
        var ev = new Ev();
        var s = ev.Start(0, 8000, Agent, name, $@"{Desktop}\{name}", $"\"{Desktop}\\{name}\"", sample: true);
        var payload = $@"{Roaming}\Microsoft\Network\svchost.exe";
        ev.File(300, 8000, s, name, EventAction.FileCreate, payload);
        var p = ev.Start(600, 8100, 8000, "svchost.exe", payload, $"\"{payload}\" -k netsvc");
        ev.Reg(900, 8100, p, "svchost.exe", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "WindowsHelper", $"\"{payload}\" -k netsvc");
        var ps = ev.Start(1200, 8200, 8100, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA");
        ev.Exit(2000, 8200, ps, "powershell.exe");
        ev.Connect(2500, 8100, p, "svchost.exe", "185.220.101.47", 8443);
        var del = ev.Start(3000, 8300, 8000, "cmd.exe", @"C:\Windows\System32\cmd.exe", $"cmd.exe /c ping 127.0.0.1 -n 3 > nul & del /f /q \"{Desktop}\\{name}\"");
        ev.Exit(3010, 8000, s, name);
        ev.File(6000, 8300, del, "cmd.exe", EventAction.FileDelete, $@"{Desktop}\{name}");
        ev.Exit(6100, 8300, del, "cmd.exe");
        return new Scenario("Stealthy dropper", ev.Events, Static(name, signature, publisher));
    }

    /// <summary>
    /// An unsigned NSIS package that only unpacks a payload into AppData, adds it to startup and lets
    /// it phone home: no stealth tricks, but nothing a real installer would do either.
    /// </summary>
    public static Scenario NsisWrappedDropper()
    {
        const string name = "free-video-converter.exe";
        var ev = new Ev();
        var s = ev.Start(0, 8500, Agent, name, $@"{Desktop}\{name}", $"\"{Desktop}\\{name}\"", sample: true);
        ev.File(100, 8500, s, name, EventAction.FileCreate, $@"{Temp}\nsx81C2.tmp\System.dll");
        var payload = $@"{Roaming}\VcHelper\vchlp32.exe";
        ev.File(400, 8500, s, name, EventAction.FileCreate, payload);
        var p = ev.Start(700, 8600, 8500, "vchlp32.exe", payload, $"\"{payload}\"");
        ev.Reg(900, 8600, p, "vchlp32.exe", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "vchlp", $"\"{payload}\" /min");
        ev.Dns(1100, 8600, p, "vchlp32.exe", "cdn-stat.example", "198.51.100.99");
        ev.Connect(1200, 8600, p, "vchlp32.exe", "198.51.100.99", 443);
        ev.Exit(1500, 8500, s, name);
        var caps = CapabilityDetector.Detect([], ["Nullsoft.NSIS.exehead", "NullsoftInst"]);
        return new Scenario("NSIS-wrapped dropper", ev.Events, Static(name, capabilities: caps));
    }
}
