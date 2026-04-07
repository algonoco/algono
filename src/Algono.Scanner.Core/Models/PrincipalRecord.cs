namespace Algono.Scanner.Core.Models;

public sealed record PrincipalRecord(
    string Id,
    string Name,
    PrincipalKind Kind,
    bool IsEnabled,
    bool IsPrivileged,
    bool IsTierZero,
    IReadOnlyList<string> Tags);
