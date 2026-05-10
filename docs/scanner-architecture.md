# Scanner Architecture

## Product direction

The scanner should be obtainable immediately. No gatekeeping ritual, no autoresponder dependency, no synthetic friction. Contact, payment, access, and support should converge into one immediate flow across web, chat, phone, email, and social.

That affects the scanner shape:

- It needs a clear CLI entrypoint.
- It needs predictable machine-readable output for agents and support flows.
- It needs a polished narrative artifact for humans.
- It cannot depend on SaaS callbacks or remote telemetry.

## Scaffold layout

The current scaffold is a thin vertical slice:

1. `IInventoryCollector`
   Collects raw directory state into a `DirectorySnapshot`.
2. `IExposureAnalyzer`
   Converts raw inventory into scores and findings.
3. `IReportEmitter`
   Emits artifacts from the snapshot and findings.
4. `ScannerEngine`
   Orchestrates the pipeline.

## Immediate next build steps

1. Decide whether the C# scaffold should wrap the current PowerShell Entra scanner or become a native Microsoft Graph collector.
2. Expand scoring from heuristics to path-aware graph analysis.
3. Swap the Markdown summary emitter for a Typst-backed PDF report emitter.
4. Add regression tests using canned Entra directory snapshots.
5. Treat local AD collection as a separate, explicitly scoped module before making AD claims in public copy.
