namespace Algono.Scanner.Core.Models;

public sealed record DirectorySnapshot(
    string DomainName,
    DateTimeOffset CapturedAtUtc,
    IReadOnlyList<PrincipalRecord> Principals,
    IReadOnlyList<PrivilegeEdge> PrivilegeEdges);
