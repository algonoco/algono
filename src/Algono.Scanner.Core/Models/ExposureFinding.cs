namespace Algono.Scanner.Core.Models;

public sealed record ExposureFinding(
    Severity Severity,
    string Title,
    string Summary,
    IReadOnlyList<string> Evidence,
    IReadOnlyList<string> ImpactedPrincipalIds);
