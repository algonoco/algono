# >_ algono

Free Entra ID privileged-access scanner for finding over-privileged Microsoft 365 / Entra identities. The paid Algono remediation toolkit is delivered separately after purchase and is not part of this public repo.

## The problem

Intern God-Mode. The pattern of privilege accumulation that happens through ticket-driven permission creep and onboarding laziness. Level-1 helpdesk with Global Admin via a nested group nobody audited. That contractor from 2019 who never got offboarded and still has privileged directory access. Every Microsoft-heavy org over 50 people has this. The question is whether they know.

## What it detects

- Stale Global Admin and other privileged Entra role assignments
- Privileged users with weak ownership or stale sign-in signals
- Group-inherited privileged role assignment paths
- Eligible privileged assignments when requested and licensed
- Guest or external accounts with privileged role exposure
- Exception-list drift for sanctioned privileged users

## Free scan

Read-only. No writes. Save it locally, inspect it, then run it against your tenant.

```powershell
# requires Microsoft.Graph module
# Install-Module Microsoft.Graph

irm https://raw.githubusercontent.com/algonoco/algono/main/prontoso/Scan-EntraPrivilegedUsers.ps1 -OutFile .\Scan-EntraPrivilegedUsers.ps1
notepad .\Scan-EntraPrivilegedUsers.ps1
.\Scan-EntraPrivilegedUsers.ps1 -TenantIdOrDomain yourtenant.onmicrosoft.com -UseDeviceAuthentication
```

Standalone by default: no local CSV or JSON sidecar files are required for the free scan.

Or download directly:
[`prontoso/Scan-EntraPrivilegedUsers.ps1`](prontoso/Scan-EntraPrivilegedUsers.ps1)

Connects to Entra via Graph API. Outputs structured JSON findings and a terminal summary.

## Full toolkit — $400

The paid remediation toolkit applies fixes from the findings report. Every write is captured in a timestamped rollback manifest before execution. Dry-run mode is supported.

Rollback reads the manifest and undoes every write. One command back to pre-remediation state.

**[Buy at algono.co](https://algono.co)** — $400 one-time, single org, perpetual license. Delivery is handled separately from this public scanner repo.

## Repo layout

```
prontoso/
  Scan-EntraPrivilegedUsers.ps1        # free — read-only audit
  PrivilegedAccessExceptions.json       # exception allowlist format
  PhonyOrgChartForSecurityAudit.csv     # Prontoso test fixture
```

`prontoso/` is the test environment — a fictional org called Prontoso used for development and validation.

## Stack

- Scripts: PowerShell, Microsoft.Graph module
- Site: static HTML/CSS, no framework, no build step
- Payments: Stripe Payment Links
