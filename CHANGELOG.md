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
- 104 automated tests, a CI workflow and publish scripts.

### Fixed
- Loading a saved analysis no longer changes the score of another analysis that is already
  open. Comparing two analyses showed the same score for both. Loading settings could also
  change the built-in default thresholds.

### Known limitations
- The Windows Sandbox provider and ETW agent have not been validated on real Windows yet.
- License not chosen yet.
