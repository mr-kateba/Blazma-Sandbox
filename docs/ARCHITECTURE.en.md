# Blazma Sandbox architecture

[العربية](ARCHITECTURE.md) · **English**

## Goals, in priority order

Security > Correctness > Stability > UX > Performance > Extra features.

## Boundaries

There are five roles, kept in separate assemblies so the boundaries are visible in code:

| Role | Assembly | Runs where | May touch |
|---|---|---|---|
| **UI** | `Blazma.App` | Host, normal user rights (`asInvoker`) | View models, services. Never parses samples itself. |
| **Analysis engine** | `Blazma.Analysis` | Host | Pure logic over events. Reads the sample only for static analysis, and only in a helper process. |
| **Host side of the sandbox** | `Blazma.Sandbox` | Host | Creates the work folders, starts Windows Sandbox, reads `out/` as untrusted input. |
| **Sandbox** | Windows Sandbox | Hypervisor-isolated VM | Disposable. Gone after every analysis. |
| **Agent** | `Blazma.Agent` | **Inside the sandbox only** | ETW tracing, snapshots, writing signed output. References only `Blazma.Contracts`. |

`Blazma.Core` holds models and interfaces with no dependencies. `Blazma.Contracts` is the
wire protocol and the only code the agent and the host share.

```
src/
  Blazma.Core           domain model, interfaces (no dependencies)
  Blazma.Contracts      host <-> agent protocol, signed files
  Blazma.Analysis       Static/ Engine/ Rules/ Pipeline/ Compare/ Text/ Yara/
  Blazma.Sandbox        Providers/WindowsSandbox  Providers/VirtualMachine (VirtualBox, Hyper-V)
                        Providers/Demo  Channel/  Isolation/  Processes/
  Blazma.Agent          in-sandbox ETW agent (win-x64, self-contained)
  Blazma.Storage        SQLite repository, settings store, paths
  Blazma.Reporting      HTML, JSON, indicator CSV, redaction
  Blazma.Intelligence   Ask Blazma, AI and reputation extension points
  Blazma.App            Avalonia UI, design system, localization
  Blazma.Cli            "blazma" command line (static, analyze, batch, export)
tests/                  Analysis, Sandbox, Integration, App
tools/Blazma.Screenshots  headless renderer for screenshots
```

### Why this structure differs from the first sketch

- **`Blazma.Contracts` was added** so the agent never references host code. Everything the host
  reads from the agent goes through one small set of DTOs, parsed defensively.
- **Static analysis runs out of process.** Parsing a hostile file is attack surface. The app
  starts a second copy of its own executable with `--static-worker <path>`, which prints a JSON
  report and exits; a crash or hang there cannot take down the UI (90 s timeout, killed on cancel).
- **The demo is a real provider** (`DemoSandboxProvider`), not a fake screen. Synthetic events go
  through the same state machine, engine, storage and reports, so the demo tests the product.
  Every demo result is labelled DEMO in the UI, History and exports.
- **One test project per area** instead of a single `Blazma.Tests`.

## Analysis pipeline

`AnalysisRunner` drives one analysis through an explicit state machine
(`AnalysisStateMachine`): the happy path is strictly linear and any active stage can move to
`Failed` or `Cancelled`. Terminal states never move.

```
Preparing → CreatingSandbox → Booting → DeployingAgent → Ready → TransferringSample
→ Analyzing → CollectingEvents → Finalizing → GeneratingReport → Completed
                                   (any active stage) → Failed | Cancelled
```

| Stage | Windows Sandbox provider |
|---|---|
| Preparing | Static report already done; provider availability check (OS, feature, agent, no other instance). |
| CreatingSandbox | `work/<id>/in` (agent, `session.json` with a fresh HMAC key, the `blazma-agent.cmd` launcher), `work/<id>/out` and `work/<id>/startup` (the launcher only); generate `blazma.wsb`. |
| Booting | Refuse to start when a sandbox is already running (`wsb list`, or the sandbox window processes on older Windows), then start `WindowsSandbox.exe blazma.wsb`. From Windows 11 24H2 that program hands the sandbox to the Store app and exits at once, so its exit means nothing: the sandbox is known to be alive from the agent's hello and heartbeats, and from `wsb list` where `wsb.exe` exists. |
| DeployingAgent | The launcher starts the agent once, from the logon command, from the sandbox user's Startup folder (some 2026 releases skip the logon command) or, after 2 minutes without a hello, from `wsb exec`; its output goes to `out/agent-start.txt`. Wait up to 8 minutes for `hello.json` (a first start can include a Store update), check the protocol version and that the agent is elevated, then **delete the key from `session.json`**. A failure quotes the last lines of `agent-start.txt` and `agent.log`. |
| TransferringSample | Copy the sample into `in/sample/`, re-check its SHA-256, write `go.json`. The agent copies it out of the share, checks the hash again, takes the baseline snapshot, starts ETW, runs it. |
| Analyzing | Read new signed event chunks every 500 ms, stream them to the Live screen, watch heartbeats, recompute a live score every 2 s. |
| CollectingEvents | Wait for `done.json`, read the last chunks and the after-snapshot. |
| Finalizing | Kill the sandbox processes, delete the work folder. Also done in `finally`, so failures and cancellation always clean up. |
| GeneratingReport | `AnalysisEngine.Process`, then save to SQLite. |

Failed and cancelled analyses are still saved, with the reason, so History shows what happened.

## Unified event model

Every collector produces `AnalysisEvent`: `Sequence`, `Timestamp`, `RelativeTime`, `Category`,
`Action`, `ProcessId`, `ParentProcessId`, `Process` (a `ProcessKey` = PID + start time, because
Windows reuses PIDs), `ProcessName`, `Target`, `Details`, `Severity`, `Source`, `CorrelationId`.

The host re-numbers sequences as it reads, so evidence references are always unique even if the
agent misbehaves.

## Analysis engine

`AnalysisEngine.Process` is deterministic:

1. **Order** events by relative time, then sequence.
2. **Process graph** (`ProcessGraph`): resolves which process instance an event belongs to, even
   with PID reuse. The *analyzed tree* is the sample, its descendants, and any process started
   from a file the tree dropped (e.g. a service launched by `services.exe`), iterated to a fixpoint.
3. **Noise filter**: events outside the analyzed tree are hidden as Windows background activity,
   except writes to persistence locations, which are kept whoever made them. If no sample process
   was identified, nothing is filtered (safe default). Users can add an allowlist.
4. **Persistence detection** against a catalog of autostart locations, each with a human
   explanation. Detections by unrelated system processes are shown but only scored when they point
   at a file the sample dropped.
5. **Correlation**: behavior chains from the sample to each process that did something
   significant (persisted, connected, ran a dropped file), written as readable steps.
6. **Rules** (`IRule`): 31 built-in rules plus user JSON rule packs. Each rule returns at most one
   finding with all its evidence, so repeated behavior is not double-counted. A failing rule is
   logged and skipped, never fatal.
7. **Risk**: the score is the sum of finding points with a cap per category, clamped to 0–100.
   Every point is listed in "Why this score?". Verdict thresholds are user-configurable.
8. **Indicators**: graded only by the findings that cite their events, or by the user's watchlist.
9. **Snapshot diff**: files, registry values, services, scheduled tasks, startup items.

### Contextual scoring

Single behaviors weigh little; combinations weigh more. PowerShell started by an installer is
`BLZ-E001` (5 points, Low). The same installer dropping an executable into AppData, running it,
that process adding a Run key and connecting out triggers `F001`, `F002`, `P001`, `N001`, `N002`
**and** the sequence rule `C001`. The tests cover both cases.

## Storage

SQLite (WAL) in `%LOCALAPPDATA%\Blazma\Sandbox\blazma-sandbox.db`, versioned migrations.

| Table | Purpose | Indexes |
|---|---|---|
| `samples` | One row per SHA-256; first/last seen, times analyzed | PK sha256 |
| `analyses` | History rows (stage, score, verdict, provider, counts, options) | started_at, sha256, verdict |
| `events` | The unified event stream (file, registry and network activity are categories of it) | (analysis, time), (analysis, category, time), (analysis, pid) |
| `events_fts` | FTS5 full-text search for global search | — |
| `processes`, `findings`, `indicators` | Searchable/listable derived rows | name, rule_id, value |
| `report_documents` | The full derived result as one gzip JSON document per analysis | PK |

Events are inserted with prepared statements in one transaction; the 100k-event test stores and
pages them in a few seconds. Lists in the UI are virtualised; Raw Events pages from the database.

Settings are a single JSON document written atomically; a corrupt file is backed up and replaced
with defaults.

## UI

Avalonia 12 (the same framework as Blazma Crosshair), MVVM with CommunityToolkit.Mvvm, DI with
Microsoft.Extensions.DependencyInjection, structured logs with Serilog (compact JSON, no sample
contents).

- **Design system** (`Styles/Tokens.axaml`, `Styles/Controls.axaml`): Blazma family tokens (graphite
  surfaces, Blazma orange `#FF6D00`, hexagon logo), typography classes, cards, keys (buttons),
  chips, badges, tabs; `RiskBadge`, `ScoreRing`, `LogoMark` controls. Orange is identity only; risk
  uses amber/red/green **with shapes and words**, never colour alone.
- **ThemeService** swaps token brushes for Dark / Midnight / Light, derives the accent ramp, density
  and corner radii.
- **Motion** transitions only apply under `.motion`, so turning off animations or enabling reduced
  motion removes them everywhere.
- **Localization**: `Loc` loads `en.json` / `ar.json` (600 keys each, tested for parity, placeholders
  and usage). Switching language re-binds every string and flips `FlowDirection`. Arabic section
  headings switch to the body font without letter-spacing so Arabic letters stay joined.
- **Errors**: global handlers log and show an in-window dialog (reason, Retry, Diagnostics) instead
  of crashing.

## Extension points

`ISandboxProvider` (VirtualBox and Hyper-V are built in, see [VIRTUAL-MACHINES.en.md](VIRTUAL-MACHINES.en.md); remote providers), `IReportExporter` (PDF), `IAiProvider` (local AI that
receives the structured result, never the sample), `IReputationProvider` (opt-in only), JSON rule
packs. A plugin system is deliberately not built until the core has been validated.

## Decision log

| Decision | Why |
|---|---|
| Avalonia over WinUI 3 / WPF | Full control of the look (Blazma identity), real RTL, headless testing and screenshots in CI, single-file deployment, and Blazma Crosshair already uses it. |
| Windows Sandbox as the first provider | Built into Windows, hypervisor-isolated, disposable, no images to manage. |
| File-based channel instead of networking | Keeps the sandbox network-free. `out/` is the only writable path and is parsed as hostile. |
| HMAC-signed output, key removed before the sample runs | A sample that wants to forge monitoring data must first extract the key from the agent's memory. |
| ETW in the agent | Kernel-level process/file/registry/network visibility without installing drivers. |
| SQLite + one compressed document per analysis | Fast paging/search on events, simple loading of the derived report. |
| No TLS interception | Out of scope for v1 by design; metadata only. |
| Managed YARA engine instead of libyara | No native parser on the host for internet-sourced rules; every search is bounded, and anything unsupported is an error rather than a silent miss. See [YARA.en.md](YARA.en.md). |
