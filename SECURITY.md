# Security

## Intended use

Blazma Sandbox is for defensive analysis, incident response, education and **authorized**
security research. Do not use it to analyze files you are not allowed to handle.

## Security model

1. **The sample never runs on the host.** Static analysis reads the file in a separate,
   short-lived helper process (the app's own executable started with `--static-worker`), with a
   timeout. Signature checks call `WinVerifyTrust` with revocation and URL retrieval disabled, so
   nothing is fetched from the network.
2. **Execution happens only in Windows Sandbox** (a hypervisor-isolated, disposable VM), with a
   generated configuration that disables networking (unless explicitly allowed for one
   analysis), vGPU, clipboard, printers, audio and video input, and enables protected client mode.
3. **Exactly two shared folders.** `in/` is read-only inside the sandbox (agent, configuration,
   sample). `out/` is the only writable folder.
4. **`out/` is hostile input.** The host only opens the exact protocol file names, never follows
   links, enforces per-file and per-analysis size limits, rejects unknown actions, clips strings,
   strips control characters, caps detail counts, and never executes or opens anything from it.
5. **Signed monitoring output.** Event chunks, heartbeats, snapshots and the done marker carry an
   HMAC-SHA256. The key is given to the agent through `in/session.json` and removed from that file
   as soon as the agent says hello, before the sample is started. Failed verification is reported
   as tampering and marks monitoring as interrupted.
6. **Teardown always happens**: on success, failure and cancellation the sandbox processes are
   stopped and the work folder is deleted.
7. **Least privilege on the host**: the app runs `asInvoker` and never asks for administrator rights.
8. **Privacy**: no uploads, no hash lookups, no telemetry. Exports redact the user name, machine name
   and profile path by default. Logs never contain file contents.
9. **Reports are safe to open**: HTML reports contain no scripts, have a restrictive
   Content-Security-Policy, and HTML-encode every value that came from the sample. CSV exports
   neutralise spreadsheet formulas.

## Known limitations (read these)

- **Validation on real Windows is pending.** The Windows Sandbox provider and the ETW agent compile
  and are covered by protocol tests, but they have not yet been exercised end to end on a real
  Windows machine. Treat real-sample results as preliminary until that is done.
- **The agent runs inside the sandbox with the sample.** A sample running with the same privileges
  can try to stop or blind the agent. Blazma detects lost heartbeats and tampered output and says
  so in the report ("Monitoring was interrupted"), but cannot prevent it.
- **Evasion.** Some programs detect virtual machines or wait longer than the analysis and behave
  differently. A quiet report is not proof of safety.
- **Windows Sandbox escapes** are outside Blazma's control; keep Windows updated.
- **Virtual machine providers (VirtualBox, Hyper-V)** are only as isolated as the VM you prepared,
  the guest `in` folder is writable by an elevated sample, and the providers have not yet been
  validated on real hypervisors. The VM must have no connected network adapter unless an analysis
  enables the network, and its snapshot is restored before and after every run. See
  [docs/VIRTUAL-MACHINES.md](docs/VIRTUAL-MACHINES.md).
- **Enabling network access** lets the sample reach the internet from the sandbox. It is off by
  default and requires explicit consent per analysis.
- **Kernel registry events carry no value data**; the agent reads the value right after the event,
  which can race with a fast-changing value.

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately through GitHub's
"Report a vulnerability" (Security tab) on this repository, with steps to reproduce. Please do not
attach live malware; describe it or share a hash.
