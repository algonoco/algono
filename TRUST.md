# Algono Scanner Trust Notes

This public repo contains the free read-only Entra privileged-access scanner.

## What The Free Scanner Does

- Connects to Microsoft Graph for the tenant you provide.
- Reads users, privileged directory roles, role assignments, and group-inherited privileged access paths.
- Writes local report artifacts under `.\artifacts\entra-privileged-scan` by default.
- Produces JSON, CSV, and Markdown summary output.

## What It Does Not Do

- It does not make Graph write calls.
- It does not install an agent.
- It does not create a service.
- It does not phone home.
- It does not upload scan results to Algono.
- It does not require your email address.

## Requested Graph Scopes

The scanner requests these delegated Microsoft Graph scopes:

- `User.Read.All`
- `AuditLog.Read.All`
- `RoleManagement.Read.Directory`
- `GroupMember.Read.All`

These are read-oriented scopes used to enumerate users, sign-in signals, role assignments, and group membership paths.

## Safer Run Pattern

Inspect before running:

```powershell
irm https://raw.githubusercontent.com/algonoco/algono/main/prontoso/Scan-EntraPrivilegedUsers.ps1 -OutFile .\Scan-EntraPrivilegedUsers.ps1
notepad .\Scan-EntraPrivilegedUsers.ps1
.\Scan-EntraPrivilegedUsers.ps1 -TenantIdOrDomain yourtenant.onmicrosoft.com -UseDeviceAuthentication
```

Validate local prerequisites without authenticating:

```powershell
.\Scan-EntraPrivilegedUsers.ps1 -TenantIdOrDomain yourtenant.onmicrosoft.com -ValidateOnly
```

## Windows Authentication Notes

Microsoft Graph PowerShell uses Web Account Manager (WAM) by default on Windows. If you run the scanner from an embedded terminal, the Microsoft sign-in window may open behind other windows.

If browser auth is awkward, use the device-code path:

```powershell
.\Scan-EntraPrivilegedUsers.ps1 -TenantIdOrDomain yourtenant.onmicrosoft.com -UseDeviceAuthentication
```

The scanner maps `-UseDeviceAuthentication` to Microsoft Graph PowerShell's `-UseDeviceCode` mode.

## Test Tenant Validation

The public scanner was tested against the Algono/Prontoso test tenant on 2026-05-10 using PowerShell 7.6.1 and Microsoft.Graph 2.36.1.

Validation run:

```powershell
.\Scan-EntraPrivilegedUsers.ps1 -TenantIdOrDomain algono.co -OutputPath .\artifacts\entra-privileged-scan-test
```

Observed output:

- User collection source: `v1.0-with-signInActivity`
- Inventory rows: `10`
- Review findings: `10`
- Findings by severity: `8 Critical`, `2 High`
- Access paths: `5 Direct`, `5 Group`
- Exception handling: `1 ExceptionApproved`, `9 ReviewRequired`
- All finding UPN domains were `algono.co`.

## Paid Toolkit Boundary

The paid remediation and rollback toolkit is not shipped in this public repo. It is delivered separately after purchase so the public scanner can remain inspectable without exposing paid remediation artifacts.
