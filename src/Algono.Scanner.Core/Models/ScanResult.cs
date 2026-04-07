namespace Algono.Scanner.Core.Models;

public sealed record ScanResult(
    DirectorySnapshot Snapshot,
    AnalysisResult Analysis,
    ScanArtifactSet Artifacts);
