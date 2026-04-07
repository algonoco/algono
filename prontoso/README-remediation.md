# Entra Privileged Remediation Runbook

This folder contains the scan, remediation, and rollback flow for the `algono.co` lab tenant.

## Files

- `Scan-EntraPrivilegedUsers.ps1`
  Produces `review-findings.json` and the scan summary.
- `Invoke-EntraPrivilegedRemediation.ps1`
  Applies or previews remediation and can roll it back from a manifest.
- `rules.csv`
  Operator-facing rule file. Edit this for sanctioned exceptions and explicit deny actions.
- `rules.normalized.json`
  Machine-normalized rule file written by the remediation script after validation.

## Rule Model

Rules are evaluated outside the scan output. `ReviewState = ExceptionApproved` is no longer the primary control plane for remediation decisions.

Supported rule modes:

- `Allow`
  Excludes matching findings from remediation.
- `Deny`
  Forces matching findings into remediation, even if they fall below the default severity threshold.

Supported rule actions:

- `Allow + Keep`
  Keep the finding out of remediation.
- `Allow + Ignore`
  Same remediation effect as `Keep`, but useful if you want the intent called out explicitly.
- `Deny + Remove`
  Force removal of the assignment or group membership.
- `Deny + Disable`
  Force remediation and disable the account during the run.

Precedence:

- `Deny` beats `Allow`.
- More specific rules beat broader rules.
- Expired rules are ignored during remediation, but called out in the summary.

## Safe Start

Validate the findings and rules locally:

```powershell
.\prontoso\Invoke-EntraPrivilegedRemediation.ps1 -ValidateOnly
```

Validate locally and confirm referenced users and groups exist in Entra:

```powershell
.\prontoso\Invoke-EntraPrivilegedRemediation.ps1 -ValidateOnly -ValidateOnline
```

If you want to validate a specific rule source:

```powershell
.\prontoso\Invoke-EntraPrivilegedRemediation.ps1 -RulesCsv .\prontoso\rules.csv -ValidateOnly
.\prontoso\Invoke-EntraPrivilegedRemediation.ps1 -RulesJson .\prontoso\rules.normalized.json -ValidateOnly -ValidateOnline
```

## Dry Run

Preview the exact actions without changing tenant state:

```powershell
.\prontoso\Invoke-EntraPrivilegedRemediation.ps1 -RulesCsv .\prontoso\rules.csv -WhatIf
```

Artifacts written under `.\artifacts\entra-privileged-remediation`:

- `remediation-manifest.json`
- `remediation-summary.md`
- `needs-manual-review.json`
- `needs-manual-review.csv`
- `rule-evaluation.json`
- `rule-evaluation.csv`

## Interactive Mode

Interactive mode is the default parameter set.

```powershell
.\prontoso\Invoke-EntraPrivilegedRemediation.ps1 -Interactive
```

Behavior:

- Uses `PromptForChoice` and `Read-Host` for guided prompts.
- Can append new sanctioned `Allow + Keep` rules into `rules.csv`.
- Writes a refreshed `rules.normalized.json`.
- Prompts for final confirmation before continuing to remediation.

Optional console picker:

```powershell
.\prontoso\Invoke-EntraPrivilegedRemediation.ps1 -Interactive -UseConsoleGui
```

`-UseConsoleGui` only activates when all of these are true:

- `Microsoft.PowerShell.ConsoleGuiTools` is installed.
- The session is interactive.
- Input and output are not redirected.

If those conditions are not met, the script falls back to plain prompts.

## Live Remediation

Run with CSV rules:

```powershell
.\prontoso\Invoke-EntraPrivilegedRemediation.ps1 -RulesCsv .\prontoso\rules.csv
```

Run with JSON rules:

```powershell
.\prontoso\Invoke-EntraPrivilegedRemediation.ps1 -RulesJson .\prontoso\rules.normalized.json
```

Disable accounts as part of remediation:

```powershell
.\prontoso\Invoke-EntraPrivilegedRemediation.ps1 -RulesCsv .\prontoso\rules.csv -DisableAccounts
```

## Rollback

Use the manifest produced by the remediation run:

```powershell
.\prontoso\Invoke-EntraPrivilegedRemediation.ps1 -RollbackManifestPath .\artifacts\entra-privileged-remediation\remediation-manifest.json
```

You can also validate a rollback manifest without applying it:

```powershell
.\prontoso\Invoke-EntraPrivilegedRemediation.ps1 -RollbackManifestPath .\artifacts\entra-privileged-remediation\remediation-manifest.json -ValidateOnly -ValidateOnline
```

## Notes

- Nested group privilege paths are not removed automatically if the user is not a direct member of the source group.
- Those cases are written to `needs-manual-review.json` and `needs-manual-review.csv`.
- Every manifest operation records `FindingId` and `AuthorizingRuleId` so the change can be defended later.
