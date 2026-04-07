using Algono.Scanner.Core.Models;

namespace Algono.Scanner.Core.Collection;

public interface IInventoryCollector
{
    Task<DirectorySnapshot> CollectAsync(ScanRequest request, CancellationToken cancellationToken);
}
