# Entra Privileged Access Scan

Tenant: `algono.co`
Generated: `2026-04-07 02:27:42Z`
User collection source: `v1.0-with-signInActivity`
Total privileged inventory rows: `10`
Review findings: `10`

## Severity

- Critical: 2
- High: 7
- Medium: 1

## Review State

- ExceptionApproved: 1
- ReviewRequired: 9

## Highest Risk Findings

| Score | Severity | User | Role | State | Dept | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 125 | Critical | creed.bratton@algono.co | Authentication Administrator | Active | Service_Desk | PrivilegedRole, ActiveAssignment, DisabledAccountStillPrivileged, NonAdminDepartment, GroupInheritedPrivilege |
| 95 | Critical | todd@algono.co | Authentication Administrator | Active | Accounting | PrivilegedRole, ActiveAssignment, NonAdminDepartment, MissingFromOrgChart, GroupInheritedPrivilege |
| 85 | High | gabe.lewis@algono.co | Helpdesk Administrator | Active | Service_Desk | PrivilegedRole, ActiveAssignment, NonAdminDepartment, GroupInheritedPrivilege |
| 85 | High | kelly.kapoor@algono.co | Helpdesk Administrator | Active | Service_Desk | PrivilegedRole, ActiveAssignment, NonAdminDepartment, GroupInheritedPrivilege |
| 85 | High | lmw@algono.co | Global Administrator | Active |  | PrivilegedRole, ActiveAssignment, NoDepartmentContext, MissingFromOrgChart |
| 85 | High | ryan.howard@algono.co | Helpdesk Administrator | Active | Service_Desk | PrivilegedRole, ActiveAssignment, NonAdminDepartment, GroupInheritedPrivilege |
| 80 | High | kelly.kapoor@algono.co | User Administrator | Active | Service_Desk | PrivilegedRole, ActiveAssignment, NonAdminDepartment |
| 80 | High | toby.flenderson@algono.co | User Administrator | Active | HR_Admin | PrivilegedRole, ActiveAssignment, NonAdminDepartment |
| 65 | High | evelyn.thorne@algono.co | Global Administrator | Active | Executive_Floor | PrivilegedRole, ActiveAssignment |
| 50 | Medium | todd@algono.co | Global Administrator | Active | Accounting | PrivilegedRole, ActiveAssignment, NonAdminDepartment, MissingFromOrgChart |
