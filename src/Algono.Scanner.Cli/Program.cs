using Algono.Scanner.Core;
using Algono.Scanner.Core.Analysis;
using Algono.Scanner.Core.Collection;
using Algono.Scanner.Core.Models;
using Algono.Scanner.Core.Reporting;

var request = ParseRequest(args);

if (!string.Equals(request.Mode, "sample", StringComparison.OrdinalIgnoreCase))
{
    Console.Error.WriteLine($"Unsupported mode '{request.Mode}'. The scaffold currently ships with 'sample' only.");
    return 1;
}

var engine = new ScannerEngine(
    new SampleInventoryCollector(),
    new HeuristicExposureAnalyzer(),
    new JsonReportEmitter());

var result = await engine.RunAsync(request, CancellationToken.None);

Console.WriteLine($"algono scanner :: {result.Snapshot.DomainName}");
Console.WriteLine($"mode           :: {request.Mode}");
Console.WriteLine($"principals     :: {result.Snapshot.Principals.Count}");
Console.WriteLine($"privilegeEdges :: {result.Snapshot.PrivilegeEdges.Count}");
Console.WriteLine($"exposureScore  :: {result.Analysis.Scorecard.DomainExposureScore}/100");
Console.WriteLine($"findings       :: {result.Analysis.Findings.Count}");
Console.WriteLine($"manifest       :: {result.Artifacts.ManifestPath}");

return 0;

static ScanRequest ParseRequest(string[] args)
{
    var domainName = "lab.algono.local";
    var outputDirectory = Path.Combine(Environment.CurrentDirectory, "artifacts", "sample");
    var mode = "sample";

    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--domain" when i + 1 < args.Length:
                domainName = args[++i];
                break;
            case "--output" when i + 1 < args.Length:
                outputDirectory = Path.GetFullPath(args[++i]);
                break;
            case "--mode" when i + 1 < args.Length:
                mode = args[++i];
                break;
        }
    }

    return new ScanRequest(domainName, outputDirectory, mode);
}
