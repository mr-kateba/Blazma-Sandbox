<p align="center">
  <img src="assets/blazma-sandbox-256.png" width="96" alt="Blazma Sandbox logo" />
</p>

<h1 align="center">Blazma Sandbox</h1>
<p align="center"><b>Analyze. Observe. Understand.</b></p>
<p align="center">Part of the Blazma family · Windows · English / العربية</p>

<p align="center">
  <img src="docs/screenshots/03-report-overview-en.png" alt="Blazma Sandbox report overview" />
</p>

Blazma Sandbox analyzes suspicious files, archives and web addresses on Windows. It inspects
a file without running it, runs it inside an isolated, disposable **Windows Sandbox** (or a
VirtualBox / Hyper-V virtual machine), watches
what it does, links the events together, and turns them into a report anyone can read:

- **What happened?** A timeline, a process tree and behavior chains.
- **Why does it matter?** Plain-language explanations and an explainable risk score.
- **What evidence supports this?** Every finding links back to the events it is based on.

Blazma is **not an antivirus**. It never calls a file "malware" from one indicator. The
score describes observed behavior; *a high score does not by itself prove that a file is
malicious*.

> Blazma Sandbox is intended for defensive analysis and **authorized** security research.

## Features

| Area | What you get |
|---|---|
| **Static analysis** | SHA-256/SHA-1, file type (including Office/PDF documents and archives), PE headers, sections and entropy, imports/exports, **imphash**, version info, offline Authenticode check, meaningful strings, **95 capability rules** in the style of capa (keylogging, injection, anti-debugging, crypto, credential access...), **extracted values** (URLs, IPs, domains, e-mails, registry paths, crypto wallets, tokens, Base64 blobs). Runs in a separate helper process and never executes the file. |
| **YARA** | Your own `.yar` files, scanned by a built-in managed engine against the sample, the files it creates and suspicious memory regions. Text, hex and regex strings with the common modifiers. No native library needed. [docs/YARA.md](docs/YARA.md) |
| **Archives** | ZIP (ZipCrypto and AES), 7z, RAR, TAR and GZip are listed without running anything. The usual sample passwords (`infected`, `malware`, `virus`) are tried automatically; the file you pick is extracted in a helper process. |
| **Web addresses** | Analyze a URL: look-alike brands, punycode, shorteners, risky domains, embedded credentials, then open it in Edge inside the sandbox (needs the real network and your consent). |
| **Isolated execution** | **Windows Sandbox** with every optional channel off, or your own **VirtualBox** or **Hyper-V** virtual machine restored from a clean snapshot before and after each run. [docs/VIRTUAL-MACHINES.md](docs/VIRTUAL-MACHINES.md) |
| **Simulated internet** | The default: no real network, but names resolve to a fake server inside the sandbox that answers HTTP and records requests, TLS server names and uploads, so downloaders and C2 check-ins show what they wanted. |
| **Monitoring** | In-sandbox agent using ETW: processes, files, registry, TCP/UDP, DNS, scheduled tasks, plus before/after snapshots, **screenshots** of the sandbox screen, **files the sample created** (copied out and analyzed), **memory regions** with injected or unpacked code, and an optional **pcapng** network capture. |
| **Interactive and user simulation** | Watch the sandbox screen live, add two minutes or finish early. Installers are clicked through automatically (Next, Install, Finish; never Cancel). |
| **Unified timeline** | One event model for everything, ordered and filterable by category, severity, process, time range and text. Virtualised for 100k+ events. |
| **Correlation** | PID-reuse-safe process tree, "dropped then executed" detection, behavior chains such as *setup.exe → created updater.exe → ran it → startup entry → contacted endpoint*. |
| **Persistence detection** | Run keys, Startup folder, scheduled tasks, services, Winlogon, IFEO, AppInit, Active Setup, each with a human explanation and the technical details. |
| **Risk engine** | 31 contextual rules with ATT&CK IDs, an **ATT&CK matrix** view, per-category caps, a "Why this score?" breakdown, sequence rules that weigh combinations, and noise suppression for Windows background activity. |
| **Reputation (opt-in)** | Local history always. **VirusTotal** and **MalwareBazaar** only if you turn them on and enter a key: the **SHA-256 is sent, never the file**. Keys are encrypted with Windows DPAPI. |
| **Reports and sharing** | Self-contained HTML (no scripts, CSP-locked), JSON with an integrity hash, indicator CSV, **STIX 2.1**, **MISP**, draft **Sigma** and **YARA** rules, and an encrypted ZIP (password `infected`) of the created files. Personal details are redacted by default. |
| **Ask Blazma** | Ask questions about a report ("Why is the score high?", "ليش أعطيت الملف High Risk؟"). Answers come from the data and cite it. Optionally a **local AI model** (Ollama, LM Studio, llama.cpp) on this computer adds a summary, labelled as AI interpretation. |
| **Command line** | `blazma static`, `analyze`, `batch`, `list`, `export`, `envs`, with exit codes that follow the verdict, for scripts and pipelines. [docs/CLI.md](docs/CLI.md) |
| **Compare analyses** | Version 1.2 vs 1.3 of the same installer: new processes, connections, domains, persistence, dropped files, score difference. |
| **Customisation** | Themes (Dark, Midnight, Light), accent colour (Blazma family shades), density, UI scale, reduced motion, dashboard cards, analysis profiles (Quick, Standard, Deep, Interactive, your own), verdict thresholds, per-rule enable/weight, JSON rule packs, YARA rules, a local watchlist, noise allowlist, editable shortcuts, report contents, retention, an optional Explorer right-click entry. |
| **Bilingual** | Full English and Arabic with real right-to-left layout. Technical terms (SHA-256, PID, IP, Registry) stay recognisable. |
| **Local first** | No telemetry and no uploads. Online lookups and AI are off until you turn them on; even then only a hash or the redacted report leaves the computer, never the file. |

## Screenshots

| | |
|---|---|
| ![Dashboard](docs/screenshots/01-dashboard-en.png) | ![Live analysis](docs/screenshots/19-live-en.png) |
| ![Timeline](docs/screenshots/04-report-timeline-en.png) | ![Process tree](docs/screenshots/05-report-processes-en.png) |
| ![Network](docs/screenshots/06-report-network-en.png) | ![Finding panel](docs/screenshots/10-finding-panel-en.png) |
| ![Ask Blazma](docs/screenshots/09-report-ask-en.png) | ![Compare](docs/screenshots/12-compare-en.png) |
| ![Settings](docs/screenshots/16-settings-detection-en.png) | ![Security Center](docs/screenshots/14-security-center-en.png) |
| ![Arabic dashboard](docs/screenshots/01-dashboard-ar.png) | ![Arabic report](docs/screenshots/03-report-overview-ar.png) |

All screenshots use the built-in **demo analysis**: synthetic events, clearly labelled DEMO,
processed by the real engine. No sample was run to make them.

## Architecture

```
Blazma.App (Avalonia UI) ──► Blazma.Analysis ──► Blazma.Core ◄── Blazma.Storage (SQLite)
        │                       (static, rules,       ▲          Blazma.Reporting (HTML/JSON)
        │                        correlation, risk)    │          Blazma.Intelligence (Ask Blazma)
        └──► Blazma.Sandbox ── Windows Sandbox provider · file channel · demo provider
                  │  ▲
     in/ (read-only)│  │ out/ (writable, untrusted, HMAC-signed)
                  ▼  │
             Blazma.Agent  (runs ONLY inside the sandbox, shares only Blazma.Contracts)
```

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the boundaries, the analysis state
machine, the data model and the design decisions, and **[SECURITY.md](SECURITY.md)** for the
security model and its limits.

## Requirements

- **To analyze real files with Windows Sandbox:** Windows 10 (1903+) or Windows 11, **Pro,
  Enterprise or Education**, with virtualization enabled in firmware and the *Windows Sandbox*
  optional feature turned on (`optionalfeatures.exe`).
- **On Windows Home** (no Windows Sandbox): use a VirtualBox virtual machine you prepare once;
  see [docs/VIRTUAL-MACHINES.md](docs/VIRTUAL-MACHINES.md). Hyper-V needs Pro or higher.
- **To build:** .NET 10 SDK. Builds on Windows, Linux and macOS; the demo analysis and all tests
  run everywhere.

## Build from source

```bash
git clone https://github.com/mr-kateba/Blazma-Sandbox
cd Blazma-Sandbox
dotnet build Blazma.Sandbox.slnx
dotnet test  Blazma.Sandbox.slnx          # 750+ tests, synthetic data only
dotnet run --project src/Blazma.App       # use "Try demo analysis" without Windows Sandbox
```

Package for Windows (self-contained, no .NET install needed on the target):

```powershell
pwsh scripts/publish.ps1        # → publish/BlazmaSandbox/BlazmaSandbox.exe, blazma.exe (CLI), agent/Blazma.Agent.exe
```

`scripts/publish.sh` produces the same package from Linux or macOS.

Regenerate the screenshots (headless, no display needed):

```bash
dotnet run --project tools/Blazma.Screenshots -- docs/screenshots en
dotnet run --project tools/Blazma.Screenshots -- docs/screenshots ar
```

## Security model in one paragraph

The sample never runs on your computer. Static parsing, archive listing and extraction happen
in short-lived helper processes. Execution happens only in Windows Sandbox (every optional
channel disabled) or in a virtual machine restored from a clean snapshot. The host shares two
folders: `in/` is read-only inside the sandbox; `out/` is the only writable one, and everything
in it is treated as hostile input: exact file names only, no links, size quotas, strict parsing,
HMAC verification, nothing executed, screenshots re-encoded by the host, created files stored
under neutral names. By default the sandbox has **no real network**: a simulated internet inside
it answers instead. The real network, online lookups and AI are off by default and need explicit
consent. Details and known limitations: [SECURITY.md](SECURITY.md).

## Roadmap

| Phase | Status |
|---|---|
| 1. Foundation: UI shell, design system, localization, database, models, demo mode | ✅ Done |
| 2. Static analysis: hashes, PE, signatures, imphash, capabilities, YARA, archives, URLs | ✅ Done |
| 3. Sandbox: Windows Sandbox, VirtualBox, Hyper-V, signed agent channel | 🧪 Implemented, needs validation on real Windows |
| 4. Monitoring: ETW events, screenshots, created files, memory, pcap, simulated internet, user simulation | 🧪 Implemented, needs validation on real Windows |
| 5. Analysis: rules, risk, correlation, persistence, snapshots, ATT&CK matrix | ✅ Done |
| 6. Reporting: report, history, search, HTML, JSON, STIX, MISP, Sigma, YARA | ✅ Done (PDF planned) |
| 7. Intelligence: Ask Blazma, opt-in hash reputation, optional local AI | ✅ Done |
| 8. Advanced: compare ✅ · command line ✅ · community intelligence, plugins | Planned |

Full list: [docs/ROADMAP.md](docs/ROADMAP.md). Features that are not built yet appear in the
app as *Planned* and are disabled; nothing pretends to work.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Detection rules can be contributed without code as
JSON rule packs: [docs/RULE-PACKS.md](docs/RULE-PACKS.md).

## License

The license has not been chosen yet; see [LICENSE](LICENSE). Bundled fonts (IBM Plex Sans
Arabic, IBM Plex Mono) are under the SIL Open Font License ([assets/fonts/OFL.txt](assets/fonts/OFL.txt)).

---

### بالعربية

**Blazma Sandbox** أداة لتحليل الملفات والملفات المضغوطة والروابط المشبوهة على Windows: تفحص الملف
دون تشغيله (البصمات، imphash، القدرات، قواعد YARA، القيم المستخرجة)، ثم تشغّله داخل Windows Sandbox
معزولة تُحذف بعد الاستخدام أو داخل جهاز افتراضي (VirtualBox أو Hyper-V)، وتراقب سلوكه مع لقطات للشاشة
وإنترنت وهمي يكشف ما يحاول الاتصال به دون شبكة حقيقية، ثم تشرح النتيجة بلغة مفهومة: ماذا حدث، ولماذا
يهم، وما الأدلة. يمكن التصدير إلى STIX وMISP وSigma وYARA، ويوجد سطر أوامر للتحليل الآلي. الواجهة بالعربية
والإنجليزية مع دعم كامل للكتابة من اليمين إلى اليسار. لا يُرفع أي ملف أبدًا؛ الفحص عبر الإنترنت والذكاء
الاصطناعي اختياريان ومعطلان افتراضيًا. النتيجة المرتفعة تصف السلوك ولا تثبت وحدها أن الملف خبيث.
