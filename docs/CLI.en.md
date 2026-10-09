# Command line

[العربية](CLI.md) · **English**

`blazma` is installed next to `BlazmaSandbox.exe`. It uses the same analysis environments,
rules, YARA folder and settings as the app, and its analyses appear in the app's History.
Help text and messages are in Arabic by default; add `--lang en` for English.

```
blazma static  <file> [--json] [--password <p>]
blazma analyze <file> [options]
blazma batch   <folder> [options] [--recursive] [--summary results.csv]
blazma list    [--limit 20] [--json]
blazma export  <analysis-id> --format html|pdf|json|stix|misp|sigma|yara --out <path>
blazma envs    [--json]
blazma help | version
```

## Examples

```powershell
# What is this file? Nothing is run.
blazma static .\invoice.exe

# Run it in Windows Sandbox for the standard two minutes, with the simulated internet.
blazma analyze .\invoice.exe --report invoice.html

# A sample shared as an encrypted ZIP (the password "infected" is tried automatically).
blazma static  .\sample.zip
blazma analyze .\sample.zip --entry payload/setup.exe

# A folder of samples overnight in a virtual machine, with a CSV summary.
blazma batch .\inbox --env virtualbox --profile deep --summary results.csv

# Indicators for your SIEM or threat-intelligence platform.
blazma export 31790d6c --format stix --out invoice.stix.json
```

## Analysis options

| Option | Meaning |
|---|---|
| `--env windows-sandbox\|virtualbox\|hyperv\|demo` | Where to run. Default: the one chosen in Settings. `demo` produces synthetic events and is labelled DEMO. |
| `--profile quick\|standard\|deep\|interactive` | Run time and what is captured. Default: `standard`. |
| `--network simulated\|offline\|internet` | Default `simulated`: no real network, a fake internet inside the sandbox records what the sample tries. |
| `--allow-internet` | Required with `--network internet`. The sample can then reach real servers. |
| `--duration <seconds>` | Override the profile's run time (15 to 1800). |
| `--entry <path>` / `--password <p>` | For archives: the file inside to run, and its password. |
| `--report <path>` | Also write an `.html`, `.pdf` or `.json` report. |
| `--lookup` | Hash-only reputation lookup with the services enabled in Settings (VirusTotal, MalwareBazaar). The file is never uploaded. |
| `--pcap` | Record the sandbox's network traffic (pcapng). |
| `--no-screenshots` | Do not capture the sandbox screen. |
| `--lang ar\|en` | Language of the output: help text, messages and finding titles. Default `ar` (Arabic); `en` gives English. |
| `--json` | Machine-readable output on stdout; progress goes to stderr. |
| `--data <folder>` | Use another data folder (also `BLAZMA_DATA`). |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done; low risk (or a command other than `analyze`/`batch`) |
| 10 | Suspicious |
| 20 | High-risk behavior |
| 30 | Critical behavior |
| 1 | Error (the analysis failed, a file could not be read) |
| 2 | Usage error |
| 3 | The analysis environment is not ready (`blazma envs` says why) |
| 4 | Cancelled (Ctrl+C) |

For `batch`, the most severe result wins. A score is evidence for a person to review, not
proof that a file is malicious.

## Safety

The command line follows the same rules as the app: static analysis and archive extraction run
in separate helper processes (`blazma --static-worker`, `--extract-worker`), the sample only runs
inside the analysis environment, and the real network needs `--allow-internet`.
