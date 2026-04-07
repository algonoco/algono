using Algono.Scanner.Core.Models;

namespace Algono.Scanner.Core.Reporting;

public interface IReportEmitter
{
    Task<ScanArtifactSet> EmitAsync(
        ScanRequest request,
        DirectorySnapshot snapshot,
        AnalysisResult analysis,
        CancellationToken cancellationToken);
}
