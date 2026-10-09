# Writing rule packs

[العربية](RULE-PACKS.md) · **English**

Blazma Sandbox ships 31 built-in rules (`BLZ-*`). You can add your own detections as JSON
files without writing or compiling code.

## Where packs live

Put `*.json` files in:

```
%LocalAppData%\Blazma\Sandbox\rules\
```

**Intelligence → Rules → Open rules folder** opens it. Packs are loaded again every time an analysis
starts, so you don't need to restart the app. To turn every custom pack off, use
the custom rule packs switch in **Settings → Detection**.

Limits are enforced on purpose:

| Limit | Value |
|---|---|
| Files read | the first 64 `*.json` files, in name order |
| File size | 1 MB per file (larger files are skipped and reported) |
| Rule ID | must start with `USR-`, at most 32 characters |
| Weight | 0–50 |
| `minCount` | 1–10 000 |

A broken pack never stops an analysis. Its errors are listed in the
**Intelligence → Rules** page.

## Example

```jsonc
{
  "pack": "My rules",
  "version": "1",
  "rules": [
    {
      "id": "USR-0001",
      "version": "1",
      "name": { "en": "Contacted our test domain", "ar": "اتصل بنطاق الاختبار" },
      "description": { "en": "Flags lookups of *.example.test.", "ar": "يرصد الاستعلام عن ‎*.example.test." },
      "category": "Network",
      "severity": "Medium",
      "weight": 8,
      "attack": [ "T1071" ],
      "match": { "action": "DnsQuery", "target": "*.example.test", "analyzedTreeOnly": true },
      "minCount": 1
    }
  ]
}
```

Comments and trailing commas are allowed, and property names are not case-sensitive.

## Fields

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | `USR-` + your suffix. A custom rule can never replace a built-in `BLZ-` rule. |
| `name.en` | yes | Title shown in the report. `name.ar` is optional and falls back to English. |
| `description` | no | Longer explanation (en/ar). Falls back to the name. |
| `category` | no | `Persistence`, `Execution`, `FileSystem`, `Registry`, `Network`, `DefenseEvasion`, `Impact`, `Static`, `Monitoring`, `Watchlist`, `Sequence`. Default `Execution`. |
| `severity` | no | `Informational`, `Low`, `Medium`, `High`, `Critical`. Default `Low`. |
| `weight` | no | Points the finding adds to the risk score. Default 5. Category caps still apply. |
| `attack` | no | MITRE ATT&CK technique IDs, shown on the finding. |
| `match` | yes | At least one condition (see below). Every condition you set must match. |
| `minCount` | no | Number of matching events needed before the rule fires. Default 1. |

### `match`

| Condition | Matches |
|---|---|
| `action` | Event action: `ProcessStart`, `ProcessExit`, `FileCreate`, `FileWrite`, `FileDelete`, `FileRename`, `RegistryKeyCreate`, `RegistryValueSet`, `RegistryValueDelete`, `RegistryKeyDelete`, `NetworkConnect`, `NetworkListen`, `NetworkSend`, `DnsQuery`, `ServiceInstall`, `ScheduledTaskCreate` |
| `category` | Event category: `Process`, `File`, `Registry`, `Network`, `Dns`, `Persistence`, `System` |
| `process` | Glob on the process image name, for example `powershell.exe` |
| `target` | Glob on the event target: a path, registry key, `host:port` or domain |
| `detailKey` + `detailValue` | Glob on one event detail, for example `CommandLine` = `*-enc*` |
| `analyzedTreeOnly` | `true` (default) only counts events from the sample and its descendants |

Globs support `*` (any run of characters) and `?` (one character). They are
case-insensitive and anchored to the whole value. Regular expressions are deliberately not
supported, so a rule pack cannot slow the engine down with a pathological pattern; every
match also has a 100 ms timeout.

## How custom findings behave

- Each finding keeps up to 25 matching events as evidence, linked to the timeline.
- The finding's origin shows the pack name, so you can always tell custom rules from
  built-in ones.
- The rule list in **Settings → Detection** can disable any rule or change its weight,
  custom or built-in.
- A custom rule adds to the score like any other rule. It is still subject to the
  per-category caps, so one noisy rule cannot push a sample to *Critical* alone.

## Sharing packs

Rule packs are plain text, so you can review them before installing. To propose a rule
for the project, open a pull request or a feature request. Include what the rule detects,
why it is not noisy on clean software, and an event that triggers it. See
[CONTRIBUTING.en.md](../CONTRIBUTING.en.md).
