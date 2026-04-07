namespace Algono.Scanner.Core.Models;

public sealed record AnalysisResult(
    ExposureScorecard Scorecard,
    IReadOnlyList<ExposureFinding> Findings);
