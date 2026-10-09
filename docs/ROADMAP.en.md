# Roadmap

[العربية](ROADMAP.md) · **English**

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
| | Behavior chains, 31 built-in rules with ATT&CK IDs, JSON rule packs | ✅ |
| | Explainable additive score with category caps, editable thresholds | ✅ |
| | Watchlist, trusted publishers, rule overrides | ✅ |
| Reports | Report view (15 tabs), history, full-text search | ✅ |
| | JSON (with integrity hash), HTML (CSP, no scripts), CSV/TXT indicators, redaction | ✅ |
| | Compare two analyses | ✅ |
| Intelligence | Ask Blazma (deterministic, cites evidence) | ✅ |
| | Local history reputation; opt-in hash-only VirusTotal and MalwareBazaar | ✅ |
| | Optional local AI (Ollama, LM Studio, llama.cpp), loopback-only by default | ✅ |
| Environments | VirtualBox and Hyper-V providers with snapshot restore | 🧪 |
| Monitoring+ | Simulated internet (fake DNS/HTTP/TLS inside the sandbox) | 🧪 |
| | Screenshots, interactive mode (extend/finish), installer clicking | 🧪 |
| | Created files and memory regions collected and analyzed; pcapng via pktmon | 🧪 |
| Static+ | Imphash, 95 capability rules, extracted values, Office/PDF detection | ✅ |
| | Managed YARA engine for the sample, created files and memory | ✅ |
| | Archives (ZIP/7z/RAR/TAR/GZip, common passwords), URL analysis | ✅ |
| Sharing | STIX 2.1, MISP, Sigma and YARA drafts, encrypted ZIP of created files | ✅ |
| | ATT&CK matrix view | ✅ |
| Tools | `blazma` command line (static, analyze, batch, export) | ✅ |
| | Explorer right-click entry (opt-in) | 🧪 |

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
| YARA modules | `pe`, `math` and `include` are not supported by the built-in engine yet | 📋 |
| Family configuration extractors | Per-family config parsers on memory dumps | 📋 |
| Community intelligence | Strictly opt-in, hashes only, never the file | 📋 |
| Plugin API | Third-party analyzers and exporters | 📋 |
| Single instance | A second launch (e.g. from Explorer) hands the file to the running app | 📋 |
| Linux / macOS samples | Different sandbox technology | 📋 |
