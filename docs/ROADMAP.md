# Roadmap

Status key: ✅ done · 🧪 implemented, needs validation on real Windows · 📋 planned.
Planned features appear in the app as **Planned** and are disabled; nothing pretends to work.

## v0.1: current (pre-release)

| Area | Item | Status |
|---|---|---|
| Foundation | Avalonia UI shell, Blazma family design system, Dark/Midnight/Light themes | ✅ |
| | Arabic + English with real RTL | ✅ |
| | Command palette (Ctrl+K), shortcuts you can change, onboarding | ✅ |
| | SQLite storage (WAL + FTS5 search), atomic settings with backup | ✅ |
| | Demo mode with three scenarios (persistent updater, quiet tool, 100k-event stress) | ✅ |
| Static analysis | Hashes, file type, entropy, PE headers/sections/imports, strings, Authenticode (offline) | ✅ |
| | Runs in a separate worker process | ✅ |
| Sandbox | `ISandboxProvider` abstraction and session lifecycle | ✅ |
| | Windows Sandbox provider (`.wsb` profile with networking and every redirection off) | 🧪 |
| | Signed file channel (HMAC-SHA256, allow-listed names, size limits) | ✅ (unit-tested) |
| Monitoring | ETW agent: process, file, registry, TCP/IP, DNS, scheduled tasks | 🧪 |
| | Before/after snapshots (Run keys, services, tasks, startup folders) | 🧪 |
| Analysis | Process tree, noise filter, persistence catalog, network map | ✅ |
| | Behavior chains, 24 built-in rules with ATT&CK IDs, JSON rule packs | ✅ |
| | Explainable additive score with category caps, editable thresholds | ✅ |
| | Watchlist, trusted publishers, rule overrides | ✅ |
| Reports | Report view (11 tabs), history, full-text search | ✅ |
| | JSON (with integrity hash), HTML (CSP, no scripts), CSV/TXT indicators, redaction | ✅ |
| | Compare two analyses | ✅ |
| Intelligence | Ask Blazma (deterministic, cites evidence) | ✅ |
| | Local history reputation | ✅ |

## Before v1.0

1. Validate the Windows Sandbox provider and the ETW agent end-to-end on Windows 10/11 Pro
   and Enterprise, including the cases where the Windows Sandbox feature is off or the
   machine has no virtualization.
2. Run a corpus of clean installers through the noise filter and tune it.
3. Choose and apply the license.
4. Code signing for the release builds.
5. Accessibility pass (screen reader names, keyboard-only flow, contrast check in all themes).

## Later

| Item | Notes | Status |
|---|---|---|
| PDF report | Printing the HTML report works today | 📋 |
| YARA scanning | Static + dropped files, user rule folders | 📋 |
| VM provider (Hyper-V) | Longer runs, snapshots, harder to fingerprint | 📋 |
| Network capture | PCAP export, optional simulated internet (fake DNS/HTTP) | 📋 |
| Local AI explanations | Local models only; must cite evidence like Ask Blazma | 📋 |
| Community intelligence | Strictly opt-in, hashes only, never the file | 📋 |
| Plugin API | Third-party analyzers and exporters | 📋 |
| Interactive mode | Click through installers inside the sandbox | 📋 |
