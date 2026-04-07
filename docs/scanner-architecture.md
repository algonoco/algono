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

1. Replace `SampleInventoryCollector` with a real Active Directory collector.
2. Add ACL, OU, GPO, and local admin collection.
3. Expand scoring from heuristics to path-aware graph analysis.
4. Swap the Markdown summary emitter for a Typst-backed PDF report emitter.
5. Add regression tests using canned directory snapshots.
