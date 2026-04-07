using System.Text;
using System.Text.Json;
using Algono.Scanner.Core.Models;

namespace Algono.Scanner.Core.Reporting;

public sealed class JsonReportEmitter : IReportEmitter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public async Task<ScanArtifactSet> EmitAsync(
        ScanRequest request,
        DirectorySnapshot snapshot,
        AnalysisResult analysis,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(request.OutputDirectory);

        var snapshotPath = Path.Combine(request.OutputDirectory, "snapshot.json");
        var analysisPath = Path.Combine(request.OutputDirectory, "analysis.json");
        var narrativePath = Path.Combine(request.OutputDirectory, "summary.md");
        var manifestPath = Path.Combine(request.OutputDirectory, "manifest.json");

        await File.WriteAllTextAsync(snapshotPath, JsonSerializer.Serialize(snapshot, JsonOptions), cancellationToken);
        await File.WriteAllTextAsync(analysisPath, JsonSerializer.Serialize(analysis, JsonOptions), cancellationToken);
        await File.WriteAllTextAsync(narrativePath, BuildNarrative(snapshot, analysis), cancellationToken);

        var manifest = new ReportManifest(
            snapshot.DomainName,
            DateTimeOffset.UtcNow,
            snapshotPath,
            analysisPath,
            narrativePath,
            "Replace JsonReportEmitter with a Typst-backed PDF emitter once the real collector is in place.");

        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifest, JsonOptions), cancellationToken);

        return new ScanArtifactSet(snapshotPath, analysisPath, narrativePath, manifestPath);
    }

    private static string BuildNarrative(DirectorySnapshot snapshot, AnalysisResult analysis)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"# Algono scan summary: {snapshot.DomainName}");
        builder.AppendLine();
        builder.AppendLine($"Captured: {snapshot.CapturedAtUtc:O}");
        builder.AppendLine($"Exposure score: {analysis.Scorecard.DomainExposureScore}/100");
        builder.AppendLine($"Tier-zero principals: {analysis.Scorecard.TierZeroPrincipalCount}");
        builder.AppendLine($"Privilege edges: {analysis.Scorecard.PrivilegedEdgeCount}");
        builder.AppendLine();
        builder.AppendLine("## Findings");
        builder.AppendLine();

        if (analysis.Findings.Count == 0)
        {
            builder.AppendLine("No heuristic findings were generated.");
            return builder.ToString();
        }

        foreach (var finding in analysis.Findings)
        {
            builder.AppendLine($"- [{finding.Severity}] {finding.Title}: {finding.Summary}");
        }

        return builder.ToString();
    }
}
