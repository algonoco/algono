namespace Algono.Scanner.Core.Models;

public sealed record ExposureScorecard(
    int DomainExposureScore,
    int TierZeroPrincipalCount,
    int PrivilegedEdgeCount,
    IReadOnlyDictionary<string, int> PrincipalScores);
