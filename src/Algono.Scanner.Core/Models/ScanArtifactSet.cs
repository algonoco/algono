namespace Algono.Scanner.Core.Models;

public sealed record ScanArtifactSet(
    string SnapshotPath,
    string AnalysisPath,
    string NarrativePath,
    string ManifestPath);
