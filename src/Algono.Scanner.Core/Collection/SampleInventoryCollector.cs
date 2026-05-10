using Algono.Scanner.Core.Models;

namespace Algono.Scanner.Core.Collection;

public sealed class SampleInventoryCollector : IInventoryCollector
{
    public Task<DirectorySnapshot> CollectAsync(ScanRequest request, CancellationToken cancellationToken)
    {
        var principals = new[]
        {
            new PrincipalRecord("grp-global-admins", "Global Administrators", PrincipalKind.Group, true, true, true, ["tier0", "built-in"]),
            new PrincipalRecord("grp-helpdesk-tier1", "Helpdesk Tier 1", PrincipalKind.Group, true, true, false, ["ops"]),
            new PrincipalRecord("svc-automation", "svc-automation", PrincipalKind.ServiceAccount, true, true, false, ["service-account"]),
            new PrincipalRecord("user-alice", "alice", PrincipalKind.User, true, false, false, ["helpdesk"]),
            new PrincipalRecord("user-bob", "bob", PrincipalKind.User, true, false, false, ["engineering"]),
            new PrincipalRecord("app-legacy", "legacy-app-registration", PrincipalKind.Computer, true, true, true, ["application"])
        };

        var edges = new[]
        {
            new PrivilegeEdge("grp-helpdesk-tier1", "grp-global-admins", PrivilegeKind.ShadowAdmin, "Nested via delegated support group.", 9),
            new PrivilegeEdge("svc-automation", "app-legacy", PrivilegeKind.Replication, "Automation identity has high-scope application access.", 10),
            new PrivilegeEdge("user-alice", "grp-helpdesk-tier1", PrivilegeKind.MemberOf, "Direct membership.", 4),
            new PrivilegeEdge("grp-global-admins", "app-legacy", PrivilegeKind.AdminTo, "Tier-zero application administration.", 10),
            new PrivilegeEdge("user-bob", "grp-helpdesk-tier1", PrivilegeKind.DelegatedControl, "Delegated support role grants privileged path.", 6)
        };

        var snapshot = new DirectorySnapshot(
            request.DomainName,
            DateTimeOffset.UtcNow,
            principals,
            edges);

        return Task.FromResult(snapshot);
    }
}
