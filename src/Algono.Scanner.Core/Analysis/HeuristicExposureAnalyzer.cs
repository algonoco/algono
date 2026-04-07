using Algono.Scanner.Core.Models;

namespace Algono.Scanner.Core.Analysis;

public sealed class HeuristicExposureAnalyzer : IExposureAnalyzer
{
    public AnalysisResult Analyze(DirectorySnapshot snapshot)
    {
        var principalsById = snapshot.Principals.ToDictionary(principal => principal.Id, StringComparer.OrdinalIgnoreCase);
        var principalScores = snapshot.Principals.ToDictionary(principal => principal.Id, _ => 0, StringComparer.OrdinalIgnoreCase);
        var findings = new List<ExposureFinding>();

        foreach (var edge in snapshot.PrivilegeEdges)
        {
            if (!principalScores.ContainsKey(edge.SourceId))
            {
                continue;
            }

            principalScores[edge.SourceId] += edge.Weight;

            if (edge.Kind is PrivilegeKind.Replication or PrivilegeKind.ShadowAdmin)
            {
                var sourceName = principalsById.GetValueOrDefault(edge.SourceId)?.Name ?? edge.SourceId;
                var targetName = principalsById.GetValueOrDefault(edge.TargetId)?.Name ?? edge.TargetId;

                findings.Add(new ExposureFinding(
                    Severity.Critical,
                    $"{sourceName} has {edge.Kind} capability",
                    $"{sourceName} reaches {targetName} through a path attackers would treat as tier-zero.",
                    [$"{edge.Kind}: {edge.Rationale}"],
                    [edge.SourceId, edge.TargetId]));
            }
        }

        foreach (var principal in snapshot.Principals.Where(principal => principal.Kind == PrincipalKind.ServiceAccount && principal.IsPrivileged))
        {
            findings.Add(new ExposureFinding(
                Severity.High,
                $"Privileged service account: {principal.Name}",
                "Service accounts with standing privilege widen the blast radius because their secrets are reused and rarely rotated aggressively.",
                ["Review logon scope, secret storage, and interactive sign-in settings."],
                [principal.Id]));
        }

        var tierZeroCount = snapshot.Principals.Count(principal => principal.IsTierZero);
        var domainExposureScore = Math.Min(
            100,
            principalScores.Values.Sum() + (tierZeroCount * 8) + (findings.Count * 5));

        var scorecard = new ExposureScorecard(
            domainExposureScore,
            tierZeroCount,
            snapshot.PrivilegeEdges.Count,
            principalScores);

        return new AnalysisResult(scorecard, findings);
    }
}
