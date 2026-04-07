using Algono.Scanner.Core.Models;

namespace Algono.Scanner.Core.Collection;

public sealed class SampleInventoryCollector : IInventoryCollector
{
    public Task<DirectorySnapshot> CollectAsync(ScanRequest request, CancellationToken cancellationToken)
    {
        var principals = new[]
        {
            new PrincipalRecord("grp-domain-admins", "Domain Admins", PrincipalKind.Group, true, true, true, ["tier0", "built-in"]),
            new PrincipalRecord("grp-server-admins", "Server Admins", PrincipalKind.Group, true, true, false, ["ops"]),
            new PrincipalRecord("svc-backup", "svc-backup", PrincipalKind.ServiceAccount, true, true, false, ["service-account"]),
            new PrincipalRecord("user-alice", "alice", PrincipalKind.User, true, false, false, ["helpdesk"]),
            new PrincipalRecord("user-bob", "bob", PrincipalKind.User, true, false, false, ["engineering"]),
            new PrincipalRecord("cmp-dc01", "dc01", PrincipalKind.Computer, true, true, true, ["domain-controller"])
        };

        var edges = new[]
        {
            new PrivilegeEdge("grp-server-admins", "grp-domain-admins", PrivilegeKind.ShadowAdmin, "Nested via delegated maintenance group.", 9),
            new PrivilegeEdge("svc-backup", "cmp-dc01", PrivilegeKind.Replication, "Service account can replicate directory changes.", 10),
            new PrivilegeEdge("user-alice", "grp-server-admins", PrivilegeKind.MemberOf, "Direct membership.", 4),
            new PrivilegeEdge("grp-domain-admins", "cmp-dc01", PrivilegeKind.AdminTo, "Tier-zero administration.", 10),
            new PrivilegeEdge("user-bob", "grp-server-admins", PrivilegeKind.DelegatedControl, "OU delegation grants server admin path.", 6)
        };

        var snapshot = new DirectorySnapshot(
            request.DomainName,
            DateTimeOffset.UtcNow,
            principals,
            edges);

        return Task.FromResult(snapshot);
    }
}
