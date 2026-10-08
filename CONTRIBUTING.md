# Contributing

Thanks for helping. These rules keep Blazma Sandbox safe and honest.

## Ground rules

1. **Priority order:** Security > Correctness > Stability > UX > Performance > extra features.
2. **Never fake a feature.** If something isn't implemented, it appears as *Planned* and is
   disabled.
3. **No verdict from one indicator.** New detections add weighted, evidence-backed findings.
   They never decide a verdict alone.
4. **Local-first.** No network calls unless the user opted in, and a sample never leaves the
   machine.
5. **Treat agent output as hostile.** Anything from inside the sandbox is validated, limited
   in size and never executed.

## Setup

- .NET SDK 10.0.100 or newer (see `global.json`)
- Windows 10/11 Pro or Enterprise with *Windows Sandbox* enabled to test real analyses.
  Everything else, including demo mode and all tests, also runs on Linux and macOS.

```bash
dotnet build Blazma.Sandbox.slnx
dotnet test Blazma.Sandbox.slnx
dotnet run --project src/Blazma.App          # demo mode works without Windows Sandbox
```

UI screenshots (headless, no display needed):

```bash
dotnet run --project tools/Blazma.Screenshots -- out en        # or: out ar · out en Report Light
```

## Where things go

| Change | Project |
|---|---|
| Models, settings, interfaces | `src/Blazma.Core` |
| Agent ↔ host messages | `src/Blazma.Contracts` (keep it small and versioned) |
| Static analysis, rules, scoring, correlation | `src/Blazma.Analysis` |
| Sandbox providers, channel, demo | `src/Blazma.Sandbox` |
| Code running *inside* the sandbox | `src/Blazma.Agent` |
| Database | `src/Blazma.Storage` |
| Exports | `src/Blazma.Reporting` |
| Ask Blazma, reputation | `src/Blazma.Intelligence` |
| UI | `src/Blazma.App` |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Checklist for a pull request

- [ ] `dotnet build` has no warnings and `dotnet test` passes.
- [ ] New logic has tests. Rules need a positive test and a test on clean activity.
- [ ] Every user-facing string is in **both** `Localization/en.json` and `ar.json`. The
      `LocalizationTests` check this.
- [ ] UI changes look right in Arabic (RTL) and in the Light theme. Attach screenshots.
- [ ] No new network access, telemetry or outbound calls.
- [ ] `CHANGELOG.md` is updated under *Unreleased*.

## Detection rules

The quickest way to contribute detection is a JSON rule pack: see
[docs/RULE-PACKS.md](docs/RULE-PACKS.md). Built-in C# rules live in
`src/Blazma.Analysis/Rules` and need:

- an ID (`BLZ-<category letter><number>`)
- an English and an Arabic name
- a weight
- ATT&CK IDs where they apply

## Security issues

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).
