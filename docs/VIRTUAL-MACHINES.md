# Analysing in your own virtual machine (VirtualBox or Hyper-V)

Besides Windows Sandbox, Blazma can run samples in a Windows virtual machine that you prepare
once. Two providers drive it:

| Provider | Id | Works on | Talks to the guest through |
|---|---|---|---|
| VirtualBox | `virtualbox` | Any Windows edition, **including Home** | `VBoxManage` and the Guest Additions |
| Hyper-V | `hyperv` | Windows 10/11 Pro, Enterprise, Education | PowerShell Direct and the integration services |

Why use a VM instead of Windows Sandbox:

- **Windows Home** has no Windows Sandbox; VirtualBox runs there.
- A full, lived-in VM is **harder for a sample to recognise** than a fresh Windows Sandbox
  (which always looks the same: same user name, no history, tiny disk).
- You choose the Windows version, installed software, language and hardware.

The same monitoring agent and the same file protocol are used, so reports look the same.

> **Status.** Both providers are covered by automated tests against simulated VirtualBox and Hyper-V
> hosts, but have not yet been exercised end to end on real hypervisors. Treat the first runs as a
> trial and please report what you find.

## What Blazma does for every analysis

1. Checks that the VM exists, the snapshot/checkpoint exists, and the VM is **not running**
   (Blazma never touches a VM you are using).
2. **Restores the clean snapshot/checkpoint.**
3. Checks the network adapters **of the restored state** and refuses to continue if one is connected,
   unless this analysis has network access enabled (see [Network](#network)).
4. Starts the VM and waits until the guest tools answer with your guest account.
5. Creates `<guest working folder>\<analysis id>\in` and `\out` in the guest, copies the agent and its
   configuration in, and starts the agent **elevated** in the background.
6. Waits for the agent's hello, then **removes the channel key** from the guest copy of the
   configuration, copies the sample in, then the go signal.
7. Every couple of seconds copies new files from the guest `out` folder to the host and reads them
   with the same strict, signature-checking reader as Windows Sandbox.
8. At the end — after success, failure **and** cancellation — **powers the VM off and restores the
   snapshot again**, then deletes the host working folder.

## Preparing the guest (both providers)

Use a VM that exists only for analysis. Nothing in it should matter to you.

1. **Install Windows 10 or 11** (64-bit). Make it look used if you like: some documents, browser
   history, a few common programs, a realistic machine and user name.
2. **Install the guest tools.**
   - VirtualBox: *Devices → Insert Guest Additions CD image…*, run the installer, restart.
   - Hyper-V: integration services ship with Windows 10/11; keep *Heartbeat* enabled in the VM's
     *Integration Services* settings. PowerShell Direct needs no extra setup.
3. **Create the administrator account Blazma signs in with.** The agent uses kernel tracing (ETW),
   which only works with a full administrator token. Pick one of:
   - **The built-in Administrator account (recommended).** It is not filtered by UAC. In an elevated
     prompt inside the guest:
     ```
     net user Administrator <password> /active:yes
     ```
     Then use `Administrator` (or `.\Administrator`) as the guest user in Blazma.
   - **Another local administrator account**, with UAC's restriction for that path lifted *in the
     analysis VM only*:
     - Hyper-V: set `LocalAccountTokenFilterPolicy` so PowerShell Direct sessions get the full token
       (the agent itself is started by a scheduled task with *highest privileges*):
       ```
       reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
       ```
     - VirtualBox: programs started by the Guest Additions get a filtered token for such accounts, so
       turn UAC off (`EnableLUA` = 0, then restart). This also changes how samples behave; prefer the
       built-in Administrator.
       ```
       reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
       ```
   The account needs a password (Windows refuses remote-style sign-ins with an empty one). If the
   agent starts without administrator rights, Blazma stops the analysis and says so.
4. **Sign that account in automatically** (for example with Sysinternals *Autologon*), so there is a
   desktop: screenshots, user simulation and samples with a window need one, and on Hyper-V the agent
   task runs in that interactive session.
5. **Optional but useful:** turn off Microsoft Defender real-time protection and tamper protection,
   Windows Update and other noisy background work in the guest, so samples are not removed before
   they run and the timeline stays readable.
6. **Disconnect the network** (see below).
7. **Shut down cleanly or leave it running at the desktop, then take the snapshot/checkpoint** and
   name it (`clean` by default). A snapshot of the *running, signed-in* VM is best: the restore
   resumes at the desktop in seconds instead of booting.

Blazma creates its working folder (`C:\Blazma` by default) itself; leave it out of the snapshot.

## Network

By default the VM must have **no connected network adapter**, in the state stored in the snapshot.
Blazma checks this after restoring the snapshot, before starting the VM.

- VirtualBox: set every adapter to **Not attached** (or untick *Enable Network Adapter*). Both count as
  disconnected.
- Hyper-V: set every network adapter's virtual switch to **Not connected**.

An analysis started with **network access enabled** accepts a connected adapter. If you deliberately
run your VM on an isolated network (for example an internal network with a fake internet service),
turn off *Require a disconnected network* in Settings; Blazma then accepts connected adapters for
every analysis — be sure that is what you want.

Simulated network (the default profile) needs no adapter: the agent answers inside the guest.

## VirtualBox

1. Install VirtualBox (any recent 7.x).
2. Prepare the guest as above. Note the VM name exactly as shown in VirtualBox Manager.
3. Take the snapshot: *Machine → Take Snapshot…*, name it `clean`.
4. In Blazma **Settings → Virtual machines**: choose VirtualBox, enter the VM name, snapshot name,
   guest user and password, and choose *Window* (watch the run) or *Headless*. Interactive analyses
   always open a window. If VirtualBox is not in `C:\Program Files\Oracle\VirtualBox`, set the path
   to `VBoxManage.exe`.

Commands Blazma runs (each value is a separate argument; after the first lookup the VM and snapshot
are addressed by UUID; the password is in a file readable only by you, deleted after each command):

```
VBoxManage list vms
VBoxManage snapshot <vm-uuid> list --machinereadable
VBoxManage showvminfo <vm-uuid> --machinereadable
VBoxManage snapshot <vm-uuid> restore <snapshot-uuid>
VBoxManage startvm <vm-uuid> --type gui|headless
VBoxManage guestproperty get <vm-uuid> /VirtualBox/GuestAdd/Version
VBoxManage guestcontrol <vm-uuid> run    --username=<user> --passwordfile=<file> --exe=<guest powershell> --timeout=60000 --wait-stdout -- <guest powershell> -NoProfile -NonInteractive -Command "exit 0"
VBoxManage guestcontrol <vm-uuid> mkdir  --username=<user> --passwordfile=<file> --parents <in\agent> <in\sample> <out>
VBoxManage guestcontrol <vm-uuid> copyto --username=<user> --passwordfile=<file> --target-directory=<guest folder> <host files…>
VBoxManage guestcontrol <vm-uuid> rm     --username=<user> --passwordfile=<file> --force <guest file>
VBoxManage guestcontrol <vm-uuid> start  --username=<user> --passwordfile=<file> --exe=<agent> -- <agent> <in> <out>
VBoxManage guestcontrol <vm-uuid> run    --username=<user> --passwordfile=<file> --exe=<guest powershell> --timeout=60000 --wait-stdout -- <guest powershell> -NoProfile -NonInteractive -EncodedCommand <list out folder>
VBoxManage guestcontrol <vm-uuid> copyfrom --username=<user> --passwordfile=<file> --target-directory=<host incoming> <guest files…>
VBoxManage controlvm <vm-uuid> poweroff
```

## Hyper-V

1. Turn on **Hyper-V** in Windows Features (including *Hyper-V Module for Windows PowerShell*), restart.
2. Blazma does not run as administrator. **Add your Windows account to the local group
   "Hyper-V Administrators"**, then sign out and in again:
   ```
   net localgroup "Hyper-V Administrators" <your user> /add
   ```
3. Prepare the guest as above. Set the checkpoint type to **Standard** (VM *Settings → Checkpoints*),
   so the checkpoint includes the running, signed-in state; then *Checkpoint* and rename it `clean`.
4. In Blazma **Settings → Virtual machines**: choose Hyper-V, enter the VM name, checkpoint name,
   guest user and password. To watch a run, open the VM in Hyper-V Manager (*Connect…*).

Blazma runs Windows PowerShell as `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
-Command -` and sends each script on standard input, so the guest password never appears on a
command line. Every value you typed is inserted as a single-quoted PowerShell literal. The scripts use:
`Get-VM`, `Get-VMCheckpoint`, `Get-VMNetworkAdapter`, `Restore-VMCheckpoint`, `Start-VM` (then wait
for the *Heartbeat* to be OK), `New-PSSession -VMId … -Credential …` (PowerShell Direct),
`Copy-Item -ToSession` / `-FromSession`, `Register-ScheduledTask` + `Start-ScheduledTask` for the agent
(interactive logon of the guest account, *highest privileges*: a process started inside a PowerShell
Direct session would be stopped when the session closes), and `Stop-VM -TurnOff -Force` followed by
`Restore-VMCheckpoint` at the end.

## Security notes and limitations

- **Isolation is what you configured.** Windows Sandbox's isolation is fixed by Microsoft; a VM is
  only as isolated as its settings. Keep shared folders, clipboard sharing, drag and drop and USB
  pass-through off in the analysis VM. Blazma does not need any of them.
- **The guest `in` folder is not read-only.** In Windows Sandbox the host maps it read-only; in a VM
  it is an ordinary folder an elevated sample could change (for example forge `control.json` to end
  its own run early). Everything that comes *back* is still verified: signed output, strict names,
  quotas, no links, nothing executed.
- **The channel key** is removed from the guest's `session.json` after the agent's hello, as in
  Windows Sandbox, but an elevated sample could recover it from the agent's memory or from free disk
  space. Tampering then cannot be detected; the snapshot restore still wipes everything afterwards.
- **Fingerprinting.** A VM is harder to spot than Windows Sandbox, not impossible: the guest tools
  (VirtualBox Guest Additions, Hyper-V integration services), virtual hardware names, the agent
  process and folder, and (VirtualBox) the short PowerShell process that lists the output folder every
  few seconds are all visible to a careful sample. A quiet report is not proof of safety.
- **Latency.** Output is copied every few seconds (each copy opens a guest session), so the live view
  lags a little behind Windows Sandbox. Heartbeats are judged by when the host *sees* a new one.
- **If the final restore fails** (for example VirtualBox is busy), Blazma logs it and the VM may be
  left as the sample left it. The next analysis restores the snapshot first anyway; you can also
  restore it by hand.

## Troubleshooting

| Message | What to do |
|---|---|
| *The virtual machine is already running* | Close/turn off the VM. Blazma restores the snapshot and starts it itself. |
| *…has a connected network adapter* | Disconnect the adapters and take the snapshot again, or enable network access for this analysis. |
| *did not become ready in time* (VirtualBox) | Install the Guest Additions in the snapshot; check the guest user name and password. |
| *could not open a PowerShell Direct session* (Hyper-V) | Check the guest credentials; the guest must be Windows 10/11 and fully started. |
| *The agent is not running as an administrator* | Use the built-in Administrator account, or see step 3 of *Preparing the guest*. |
| *The agent task did not start* (Hyper-V) | The guest account must be signed in (auto sign-in, or a checkpoint taken at the desktop). |
| *Permission to manage virtual machines* fails | Join the *Hyper-V Administrators* group, sign out and in. |
