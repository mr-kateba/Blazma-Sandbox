# Gap analysis: what other tools leave out

Before building Blazma Sandbox we looked at the tools people already use to answer the
question *"what does this file do?"*. Each one is good at something. This page lists what
each one does not do well for a **single analyst on a single Windows machine**, and what
Blazma Sandbox does about it.

This is not a claim that Blazma Sandbox is better than these tools. Commercial sandboxes run
fleets of instrumented VMs and have years of signatures behind them. Blazma Sandbox's aim is
narrower: it runs locally and explains its reasoning.

## The tools

| Tool | What it does well | What it lacks for our user |
|---|---|---|
| **ANY.RUN** | Interactive cloud sandbox with a live view and a large community | Samples are uploaded to a third party, and free-tier tasks are public. Needs internet. The score is hard to reproduce. |
| **Hybrid Analysis / Falcon Sandbox** | Free public reports and good static and dynamic coverage | Upload-only, and reports are public by default. You can't run it offline or change how it scores. |
| **Joe Sandbox** | Very deep analysis and many OS targets | Commercial, cloud or on-prem appliance. Heavy for one person. |
| **Cuckoo / CAPE** | Open source and extensible | Linux host, several VMs and a lot of setup. Cuckoo is unmaintained. No desktop UI and no Arabic. |
| **Process Monitor (Procmon)** | Perfect raw visibility | Collects everything and draws no conclusions. No sandbox, no score, no report. The analyst does the correlation by hand. |
| **Sandboxie Plus** | Easy local isolation | Contains the program but does not analyse it. No timeline and no verdict. |
| **Windows Sandbox (plain)** | Built in and disposable | A clean desktop, nothing more: no monitoring, no report, no history. |
| **VirusTotal** | Many engines and reputation data | Mostly static and reputation. Uploading may leak a private file. Answers "do engines flag it?", not "what did it do?". |

## Gaps and what Blazma Sandbox adds

### 1. Privacy: nothing leaves the machine
**Gap:** the convenient tools are cloud tools, and a confidential document or an internal
build should not be uploaded to a public service.
**Blazma:** local-first. No uploads, no telemetry and no cloud scoring. Reputation comes only
from your own history (`LocalHistoryReputationProvider`). Online features are shown as
*Planned* and are opt-in by design.

### 2. Explainable scoring
**Gap:** most sandboxes show a number or a red label. The analyst can't see *why* the
number is 72, or what would change it.
**Blazma:** an additive score. Every point comes from a named finding that has a weight,
links to its evidence events, and appears in the score breakdown. Per-category caps stop
one noisy category from dominating. One indicator alone never yields "malicious", and the
report says so in its disclaimer.

### 3. Evidence you can click
**Gap:** findings and raw events are often in separate places.
**Blazma:** every finding links to the exact timeline events, process and ATT&CK technique
behind it. Each fact is labeled as an observed fact or a rule inference.

### 4. Behavior chains instead of event soup
**Gap:** Procmon-style tools give you 100,000 rows.
**Blazma:** a correlation engine that builds chains, for example *drop file → set Run key
→ start the dropped file → connect out*. It also uses an analyzed-tree filter and a noise
filter, so system background activity doesn't drown the sample.

### 5. Customizable detection without code
**Gap:** changing detection means writing Python signatures (CAPE) or asking a vendor.
**Blazma:**
- JSON rule packs ([RULE-PACKS.md](RULE-PACKS.md)).
- Turn any rule on or off, or change its weight.
- Adjustable verdict thresholds.
- Watchlist of domains, IPs, paths and hashes.
- Noise allowlist and trusted publishers.
- Analysis profiles (quick, standard, deep, or your own).

### 6. Customizable app, not only detection
**Gap:** most analysis tools have one fixed look and one language.
**Blazma:**
- Themes: Dark, Midnight and Light.
- Accent colors (Blazma orange by default), density and UI scale.
- Reduced motion.
- Dashboard widgets you can turn on or off.
- Shortcuts you can change.
- Report contents and redaction defaults.
- Notification, storage and retention settings.
- Every setting is in one searchable Settings page and saved atomically, with a backup if
  the file is corrupted.

### 7. Arabic as a first-class language
**Gap:** none of the tools above has an Arabic interface or Arabic reports.
**Blazma:** full Arabic UI with real right-to-left layout (not only translated text), Arabic
reports, and fonts chosen for both scripts (IBM Plex Sans Arabic and IBM Plex Mono).

### 8. Sharing reports without leaking
**Gap:** reports often contain the analyst's user name, machine name and internal paths.
**Blazma:**
- Redaction when exporting.
- JSON reports carry a SHA-256 integrity hash, so tampering is visible.
- HTML reports have a strict CSP and no scripts, so they are safe to open.
- CSV exports neutralize spreadsheet formulas.

### 9. Comparing two runs
**Gap:** "is version 1.3 of this tool doing something new compared to 1.2?" usually means
diffing reports by hand.
**Blazma:** a compare view that shows the score change, plus findings, processes,
endpoints, domains, dropped files and persistence added or removed between two analyses.

### 10. Asking questions about a report
**Gap:** reports are long, and beginners don't know where to look.
**Blazma:** *Ask Blazma* answers questions like "does it persist?" or "what did it contact?"
directly from the report. It is deterministic and needs no model or internet. Every answer
cites its events and says whether it is an observed fact or an inference.

### 11. Defense in depth around the analyzer itself
**Gap:** parsing a hostile file is itself an attack surface.
**Blazma:**
- Static parsing runs in a separate worker process.
- The sandbox profile disables networking, clipboard, GPU, audio, video and printer.
  Networking is the only one you can turn on, and it shows a warning.
- The only channel between sandbox and host is a file folder. Every file in it is
  HMAC-signed, size-limited and checked against an allow-list of names.
- Anything the agent sends back is treated as untrusted input.
- Details: [SECURITY.md](../SECURITY.md).

### 12. Honest about its limits
**Gap:** some tools hide when monitoring broke or the sample did nothing.
**Blazma:**
- A *monitoring interrupted* finding when the agent stops reporting.
- An event-cap note when the event limit is reached.
- A clear "no significant behavior observed" result. This is not the same as "safe".
- Features that are not built yet appear as *Planned* and are disabled.

## Still behind other tools (on the roadmap)

| Area | Status |
|---|---|
| Full VM provider (Hyper-V/VirtualBox) to evade sandbox detection | Planned |
| Memory analysis and unpacking | Not planned for v1 |
| YARA scanning | Planned |
| Network traffic capture (PCAP) and TLS inspection | Planned |
| PDF reports | Planned |
| Local AI explanations | Planned, local model only |
| Community intelligence sharing | Planned, opt-in only |
| Validation of the Windows Sandbox provider and ETW agent on real hardware | **Needed before the first release** |

See [ROADMAP.md](ROADMAP.md).
