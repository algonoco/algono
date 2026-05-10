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
- The real Entra collector lives in `prontoso/Scan-EntraPrivilegedUsers.ps1`.
- This C# scaffold is retained as a future typed scanner/reporting path.

## Run

```powershell
dotnet run --project .\src\Algono.Scanner.Cli\Algono.Scanner.Cli.csproj -- --mode sample --domain contoso.onmicrosoft.com
```
