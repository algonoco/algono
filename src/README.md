# Algono Scanner

This directory contains the scanner scaffold, separate from the marketing site at the repo root.

## Projects

- `Algono.Scanner.Core`
  Scanner contracts, models, analysis, and report emission.
- `Algono.Scanner.Cli`
  Command-line entrypoint for running scans and emitting artifacts.

## Current state

The scaffold is intentionally narrow:

- `sample` mode is implemented end to end.
- Artifacts are emitted as JSON plus a Markdown narrative.
- The real Active Directory collector is not implemented yet.

## Run

```powershell
dotnet run --project .\src\Algono.Scanner.Cli\Algono.Scanner.Cli.csproj -- --mode sample --domain corp.example.local
```
