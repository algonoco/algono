namespace Algono.Scanner.Core.Models;

public sealed record PrivilegeEdge(
    string SourceId,
    string TargetId,
    PrivilegeKind Kind,
    string Rationale,
    int Weight);
