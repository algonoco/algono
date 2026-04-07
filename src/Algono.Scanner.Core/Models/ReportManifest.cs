namespace Algono.Scanner.Core.Models;

public sealed record ReportManifest(
    string DomainName,
    DateTimeOffset GeneratedAtUtc,
    string SnapshotPath,
    string AnalysisPath,
    string NarrativePath,
    string NextStep);
