# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Desktop app (Avalonia) in the Blazma family style: graphite surfaces, Blazma orange
  accent, hexagon mark.
- Dark, Midnight and Light themes, accent colors from the Blazma family palette, density,
  UI scale and reduced motion.
- Full Arabic and English interfaces with right-to-left layout.
- Command palette (Ctrl+K), shortcuts you can change, onboarding, Security Center and
  searchable Settings.
- Static analysis: hashes, file type, entropy, PE parsing, strings and offline Authenticode
  check. Parsing runs in a separate worker process.
- Sandbox layer: provider abstraction, a Windows Sandbox provider with a locked-down `.wsb`
  profile, and an HMAC-signed file channel.
- In-sandbox ETW monitoring agent and before/after snapshots.
- Analysis engine:
  - Process graph, noise filter, persistence catalog and network map.
  - Behavior chains and 24 rules mapped to MITRE ATT&CK.
  - Explainable risk score with category caps.
- JSON rule packs, rule overrides, watchlist, trusted publishers and analysis profiles.
- Reports:
  - Report view, history and full-text search.
  - JSON export with an integrity hash, HTML export with a strict CSP, and CSV/TXT
    indicator exports.
  - Redaction.
- Comparing two analyses.
- Ask Blazma: deterministic questions and answers over a report, citing the evidence.
- Demo mode with three scenarios.
- More environments: VirtualBox and Hyper-V virtual machines restored from a clean snapshot
  around every run, for Windows Home users and longer analyses.
- Simulated internet (the new default): names resolve to a fake server inside the sandbox
  that records HTTP requests, TLS server names and uploads, with no real network.
- Screenshots of the sandbox screen, shown live and in the report; interactive mode with
  "two more minutes" and "finish now"; automatic clicking through installers.
- Files the sample creates are copied out (under neutral names), hashed and analyzed;
  memory regions with injected or unpacked code are dumped and scanned; optional pcapng.
- Static analysis: imphash, 95 capability rules, extracted values (URLs, wallets, tokens,
  Base64), Office/PDF detection, archive listing (ZIP/7z/RAR/TAR/GZip, common sample
  passwords tried) and extraction of one entry in a helper process.
- Built-in managed YARA engine and a YARA rules section on the Intelligence page.
- Web address analysis: look-alike brands, punycode, shorteners; opened in Edge inside the
  sandbox when the real network is allowed.
- Opt-in hash-only reputation (VirusTotal, MalwareBazaar) with keys protected by DPAPI.
- Optional local AI (Ollama, LM Studio, llama.cpp) in Ask Blazma, loopback-only by default.
- Report tabs for screenshots, created files and memory, code (capabilities, YARA, extracted
  values) and an ATT&CK matrix; seven new rules (31 in total).
- Exports to STIX 2.1, MISP, draft Sigma and YARA rules, and an encrypted ZIP of created files.
- `blazma` command line: static, analyze, batch, list, export, envs, with verdict exit codes.
- Optional "Analyze with Blazma Sandbox" entry in the Explorer right-click menu.
- 750+ automated tests, a CI workflow and publish scripts.

### Fixed
- Loading a saved analysis no longer changes the score of another analysis that is already
  open. Comparing two analyses showed the same score for both. Loading settings could also
  change the built-in default thresholds.

### Known limitations
- The Windows Sandbox provider, the virtual machine providers and the agent (ETW, screen
  capture, simulated internet, installer clicking, memory dumps, pktmon) have not been
  validated on real Windows yet.
- License not chosen yet.
