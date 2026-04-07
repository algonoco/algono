# >_ algono

AD/Entra identity remediation toolkit. Finds over-privileged accounts, fixes them, rolls back every write on command.

## The problem

Intern God-Mode. The pattern of privilege accumulation that happens through ticket-driven permission creep and onboarding laziness. Interns with Domain Admin. Level-1 helpdesk with Global Admin via a nested group nobody audited. That contractor from 2019 who never got offboarded and still has Directory.Read on your tenant. Every org over 50 people has this. The question is whether they know.

## What it detects

- Stale Domain Admin / Global Admin — no MFA, no recent logon, no documented owner
- Service accounts with interactive login rights — password age > 365 days, can authenticate as a human
- Nested group privilege escalation — unprivileged group nested into admin group, effective Domain Admin
- Entra app registrations with owner-level Graph permissions — no expiry, no assigned owner
- Orphaned guest accounts with directory access — Directory.Read or above, no recent sign-in
- Managed identity over-scope — Contributor or Owner at subscription scope

## Free scan

Read-only. No writes. Safe to run in production now.

```powershell
# requires Microsoft.Graph module
# Install-Module Microsoft.Graph

iwr https://raw.githubusercontent.com/algonoco/algono/main/prontoso/Scan-EntraPrivilegedUsers.ps1 | iex
```

Or download directly:
[`prontoso/Scan-EntraPrivilegedUsers.ps1`](prontoso/Scan-EntraPrivilegedUsers.ps1)

Connects to Entra via Graph API. Outputs structured JSON findings and a terminal summary.

## Full toolkit — $400

[`prontoso/Invoke-EntraPrivilegedRemediation.ps1`](prontoso/Invoke-EntraPrivilegedRemediation.ps1) — applies fixes from the findings report. Every write captured in a timestamped rollback manifest before execution. Dry-run mode supported.

Rollback reads the manifest and undoes every write. One command back to pre-remediation state.

**[Buy at algono.co](https://algono.co)** — $400 one-time, single org, perpetual license. GitHub repo invite sent to payment email.

## Repo layout

```
prontoso/
  Scan-EntraPrivilegedUsers.ps1        # free — read-only audit
  Invoke-EntraPrivilegedRemediation.ps1 # paid — remediation + rollback
  rules.csv                             # detection rules
  rules.normalized.json                 # normalized rules (machine-readable)
  PrivilegedAccessExceptions.json       # exception allowlist format
  PhonyOrgChartForSecurityAudit.csv     # Prontoso test fixture
  ProntosoTenantSeed.json               # Prontoso tenant seed data
  Seed-ProntosoTenant.ps1               # seeds a test tenant with Prontoso data
  README-remediation.md                 # remediation runbook
```

`prontoso/` is the test environment — a fictional org called Prontoso used for development and validation.

## Stack

- Scripts: PowerShell, Microsoft.Graph module
- Site: static HTML/CSS, no framework, no build step
- Chat: Cloudflare Worker proxying Gemini 2.5 Flash
- Payments: Stripe Payment Links
