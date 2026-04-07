namespace Algono.Scanner.Core.Models;

public sealed record ScanRequest(
    string DomainName,
    string OutputDirectory,
    string Mode);
