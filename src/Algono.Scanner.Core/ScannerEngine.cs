using Algono.Scanner.Core.Analysis;
using Algono.Scanner.Core.Collection;
using Algono.Scanner.Core.Models;
using Algono.Scanner.Core.Reporting;

namespace Algono.Scanner.Core;

public sealed class ScannerEngine
{
    private readonly IInventoryCollector _collector;
    private readonly IExposureAnalyzer _analyzer;
    private readonly IReportEmitter _reportEmitter;

    public ScannerEngine(
        IInventoryCollector collector,
        IExposureAnalyzer analyzer,
        IReportEmitter reportEmitter)
    {
        _collector = collector;
        _analyzer = analyzer;
        _reportEmitter = reportEmitter;
    }

    public async Task<ScanResult> RunAsync(ScanRequest request, CancellationToken cancellationToken)
    {
        var snapshot = await _collector.CollectAsync(request, cancellationToken);
        var analysis = _analyzer.Analyze(snapshot);
        var artifacts = await _reportEmitter.EmitAsync(request, snapshot, analysis, cancellationToken);

        return new ScanResult(snapshot, analysis, artifacts);
    }
}
