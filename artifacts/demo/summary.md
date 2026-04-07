# Algono scan summary: corp.algono.local

Captured: 2026-04-04T06:44:56.7738480+00:00
Exposure score: 70/100
Tier-zero principals: 2
Privilege edges: 5

## Findings

- [Critical] Server Admins has ShadowAdmin capability: Server Admins reaches Domain Admins through a path attackers would treat as tier-zero.
- [Critical] svc-backup has Replication capability: svc-backup reaches dc01 through a path attackers would treat as tier-zero.
- [High] Privileged service account: svc-backup: Service accounts with standing privilege widen the blast radius because their secrets are reused and rarely rotated aggressively.
