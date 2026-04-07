using Algono.Scanner.Core.Models;

namespace Algono.Scanner.Core.Analysis;

public interface IExposureAnalyzer
{
    AnalysisResult Analyze(DirectorySnapshot snapshot);
}
