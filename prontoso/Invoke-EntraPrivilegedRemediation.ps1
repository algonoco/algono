[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$TenantIdOrDomain = 'algono.co',
    [string]$FindingsPath = '.\artifacts\entra-privileged-scan\review-findings.json',
    [string]$OutputPath = '.\artifacts\entra-privileged-remediation',
    [ValidateSet('Critical', 'High', 'Medium', 'Low')]
    [string]$MinimumSeverity = 'High',
    [switch]$DisableAccounts,
    [string]$RollbackManifestPath,
    [switch]$UseDeviceAuthentication,
    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RequiredScopes = @(
    'RoleManagement.ReadWrite.Directory',
    'GroupMember.ReadWrite.All',
    'User.Read.All',
    'User.EnableDisableAccount.All'
)

$SeverityRank = @{
    Low = 1
    Medium = 2
    High = 3
    Critical = 4
}

function Write-Info {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Test-GraphNotFound {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $message = [string]$ErrorRecord.Exception.Message
    return $message -match '404' -or $message -match 'Request_ResourceNotFound' -or $message -match 'NotFound'
}

function Get-GraphContextStatus {
    $context = Get-MgContext
    if ($null -eq $context) {
        return [pscustomobject]@{
            Connected = $false
            MissingScopes = $RequiredScopes
            Context = $null
        }
    }

    $existingScopes = @($context.Scopes)
    $missingScopes = @($RequiredScopes | Where-Object { $_ -notin $existingScopes })

    [pscustomobject]@{
        Connected = $true
        MissingScopes = $missingScopes
        Context = $context
    }
}

function Ensure-GraphConnection {
    if ($ValidateOnly) {
        Write-Info 'ValidateOnly set. Skipping Graph authentication.'
        return
    }

    $status = Get-GraphContextStatus
    $mustReconnect = -not $status.Connected -or $status.MissingScopes.Count -gt 0

    if ($status.Connected -and $status.Context.TenantId -and $TenantIdOrDomain -and ($status.Context.TenantId -ne $TenantIdOrDomain) -and ($status.Context.Account -notlike "*@$TenantIdOrDomain")) {
        $mustReconnect = $true
    }

    if ($mustReconnect) {
        Write-Info ("Connecting to Microsoft Graph for tenant '{0}' with scopes: {1}" -f $TenantIdOrDomain, ($RequiredScopes -join ', '))
        if ($UseDeviceAuthentication) {
            Connect-MgGraph -TenantId $TenantIdOrDomain -Scopes $RequiredScopes -UseDeviceAuthentication -NoWelcome | Out-Null
        }
        else {
            Connect-MgGraph -TenantId $TenantIdOrDomain -Scopes $RequiredScopes -NoWelcome | Out-Null
        }
    }
    else {
        Write-Info ("Reusing Graph context for {0}" -f $status.Context.Account)
    }
}

function Invoke-GraphJson {
    param(
        [string]$Uri,
        [string]$Method = 'GET',
        [object]$Body,
        [hashtable]$Headers
    )

    $invokeParameters = @{
        Method = $Method
        Uri = $Uri
        OutputType = 'PSObject'
    }

    if ($Headers) {
        $invokeParameters.Headers = $Headers
    }

    if ($PSBoundParameters.ContainsKey('Body')) {
        $invokeParameters.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 12 }
        $invokeParameters.ContentType = 'application/json'
    }

    Invoke-MgGraphRequest @invokeParameters
}

function Invoke-GraphCollection {
    param(
        [string]$Uri,
        [hashtable]$Headers
    )

    $results = New-Object System.Collections.Generic.List[object]
    $nextUri = $Uri

    while ($nextUri) {
        $response = Invoke-GraphJson -Uri $nextUri -Headers $Headers

        if ($null -ne $response.value) {
            foreach ($item in $response.value) {
                $results.Add($item)
            }
        }
        elseif ($null -ne $response) {
            $results.Add($response)
        }

        $nextUri = $response.'@odata.nextLink'
    }

    return @($results)
}

function Escape-ODataString {
    param([string]$Value)

    return $Value.Replace("'", "''")
}

function Get-CurrentRoleAssignments {
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$DirectoryScopeId
    )

    $filter = [Uri]::EscapeDataString(("principalId eq '{0}' and roleDefinitionId eq '{1}' and directoryScopeId eq '{2}'" -f $PrincipalId, $RoleDefinitionId, (Escape-ODataString -Value $DirectoryScopeId)))
    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=$filter&`$select=id,principalId,roleDefinitionId,directoryScopeId"
    return @(Invoke-GraphCollection -Uri $uri)
}

function Get-DirectGroupMembership {
    param(
        [string]$GroupId,
        [string]$UserId
    )

    $filter = [Uri]::EscapeDataString(("id eq '{0}'" -f $UserId))
    $uri = "https://graph.microsoft.com/v1.0/groups/{0}/members/microsoft.graph.user?`$filter={1}&`$count=true&`$select=id,userPrincipalName,displayName" -f $GroupId, $filter
    return @(Invoke-GraphCollection -Uri $uri -Headers @{ ConsistencyLevel = 'eventual' })
}

function Disable-UserAccount {
    param(
        [string]$UserId,
        [string]$UserPrincipalName
    )

    $user = Invoke-GraphJson -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select=id,userPrincipalName,accountEnabled" -f $UserId)
    if (-not [bool]$user.accountEnabled) {
        return [pscustomobject]@{
            PreviousAccountEnabled = $false
            Action = 'AlreadyDisabled'
        }
    }

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Disable user account')) {
        Invoke-GraphJson -Uri ("https://graph.microsoft.com/v1.0/users/{0}" -f $UserId) -Method 'PATCH' -Body @{ accountEnabled = $false } | Out-Null
        return [pscustomobject]@{
            PreviousAccountEnabled = $true
            Action = 'Disabled'
        }
    }

    [pscustomobject]@{
        PreviousAccountEnabled = $true
        Action = 'WhatIf'
    }
}

function Restore-UserAccount {
    param(
        [string]$UserId,
        [bool]$AccountEnabled,
        [string]$UserPrincipalName
    )

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Restore user account state')) {
        Invoke-GraphJson -Uri ("https://graph.microsoft.com/v1.0/users/{0}" -f $UserId) -Method 'PATCH' -Body @{ accountEnabled = $AccountEnabled } | Out-Null
        return 'Restored'
    }

    return 'WhatIf'
}

Ensure-Directory -Path $OutputPath

if ($ValidateOnly) {
    if ($RollbackManifestPath) {
        if (-not (Test-Path -LiteralPath $RollbackManifestPath)) {
            throw "Rollback manifest not found: $RollbackManifestPath"
        }

        $null = Get-Content -LiteralPath $RollbackManifestPath -Raw | ConvertFrom-Json -Depth 12
    }
    else {
        if (-not (Test-Path -LiteralPath $FindingsPath)) {
            throw "Findings file not found: $FindingsPath"
        }

        $null = Get-Content -LiteralPath $FindingsPath -Raw | ConvertFrom-Json -Depth 12
    }

    Write-Info 'Validation complete.'
    return
}

Ensure-GraphConnection

if ($RollbackManifestPath) {
    $manifest = Get-Content -LiteralPath $RollbackManifestPath -Raw | ConvertFrom-Json -Depth 12
    $rollbackResults = New-Object System.Collections.Generic.List[object]

    foreach ($operation in @($manifest.operations | Sort-Object Sequence -Descending)) {
        switch ($operation.OperationType) {
            'DeleteRoleAssignment' {
                $body = @{
                    principalId = $operation.PrincipalId
                    roleDefinitionId = $operation.RoleDefinitionId
                    directoryScopeId = $operation.DirectoryScopeId
                }

                if ($PSCmdlet.ShouldProcess($operation.PrincipalDisplayName, 'Recreate role assignment')) {
                    $created = Invoke-GraphJson -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' -Method 'POST' -Body $body
                    $rollbackResults.Add([pscustomobject]@{
                            Sequence = $operation.Sequence
                            OperationType = $operation.OperationType
                            Status = 'Restored'
                            RestoredObjectId = $created.id
                            Target = $operation.PrincipalDisplayName
                        })
                }
            }
            'RemoveGroupMember' {
                $body = @{
                    '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($operation.UserId)"
                }

                if ($PSCmdlet.ShouldProcess($operation.UserPrincipalName, 'Re-add group membership')) {
                    Invoke-GraphJson -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/members/`$ref" -f $operation.GroupId) -Method 'POST' -Body $body | Out-Null
                    $rollbackResults.Add([pscustomobject]@{
                            Sequence = $operation.Sequence
                            OperationType = $operation.OperationType
                            Status = 'Restored'
                            RestoredObjectId = $operation.GroupId
                            Target = $operation.UserPrincipalName
                        })
                }
            }
            'DisableUser' {
                $status = Restore-UserAccount -UserId $operation.UserId -AccountEnabled ([bool]$operation.PreviousAccountEnabled) -UserPrincipalName $operation.UserPrincipalName
                $rollbackResults.Add([pscustomobject]@{
                        Sequence = $operation.Sequence
                        OperationType = $operation.OperationType
                        Status = $status
                        RestoredObjectId = $operation.UserId
                        Target = $operation.UserPrincipalName
                    })
            }
            default {
                throw "Unsupported rollback operation type '$($operation.OperationType)'."
            }
        }
    }

    $rollbackResultPath = Join-Path $OutputPath 'rollback-results.json'
    $rollbackResults | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $rollbackResultPath
    Write-Info ("Rollback results written to {0}" -f $rollbackResultPath)
    return
}

if (-not (Test-Path -LiteralPath $FindingsPath)) {
    throw "Findings file not found: $FindingsPath"
}

$findings = @(Get-Content -LiteralPath $FindingsPath -Raw | ConvertFrom-Json -Depth 12)
$minimumRank = $SeverityRank[$MinimumSeverity]

$candidateFindings = @($findings | Where-Object {
        $_.ReviewState -ne 'ExceptionApproved' -and
        $SeverityRank[$_.Severity] -ge $minimumRank
    })

$manifest = [ordered]@{
    generatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    tenant = $TenantIdOrDomain
    minimumSeverity = $MinimumSeverity
    disableAccounts = [bool]$DisableAccounts
    findingsCount = $candidateFindings.Count
    operations = @()
}

$seenRoleAssignments = @{}
$seenGroupMemberships = @{}
$seenDisabledUsers = @{}
$sequence = 1

foreach ($finding in $candidateFindings) {
    if ($finding.AccessPath -eq 'Direct') {
        $roleKey = '{0}|{1}|{2}' -f $finding.UserId, $finding.RoleDefinitionId, $finding.DirectoryScopeId
        if (-not $seenRoleAssignments.ContainsKey($roleKey)) {
            $seenRoleAssignments[$roleKey] = $true
            $currentAssignments = Get-CurrentRoleAssignments -PrincipalId $finding.UserId -RoleDefinitionId $finding.RoleDefinitionId -DirectoryScopeId $finding.DirectoryScopeId
            foreach ($assignment in $currentAssignments) {
                if ($PSCmdlet.ShouldProcess($finding.UserPrincipalName, ("Delete direct role assignment {0}" -f $finding.RoleDisplayName))) {
                    Invoke-GraphJson -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/{0}" -f $assignment.id) -Method 'DELETE' | Out-Null
                    $status = 'Deleted'
                }
                else {
                    $status = 'WhatIf'
                }

                $manifest.operations += [pscustomobject]@{
                    Sequence = $sequence
                    OperationType = 'DeleteRoleAssignment'
                    Status = $status
                    RoleAssignmentId = $assignment.id
                    PrincipalId = $finding.UserId
                    PrincipalDisplayName = $finding.DisplayName
                    UserPrincipalName = $finding.UserPrincipalName
                    RoleDefinitionId = $finding.RoleDefinitionId
                    RoleDisplayName = $finding.RoleDisplayName
                    DirectoryScopeId = $finding.DirectoryScopeId
                    FindingSeverity = $finding.Severity
                }
                $sequence++
            }
        }
    }
    elseif ($finding.AccessPath -eq 'Group' -and $finding.SourceGroupId) {
        $groupKey = '{0}|{1}' -f $finding.SourceGroupId, $finding.UserId
        if (-not $seenGroupMemberships.ContainsKey($groupKey)) {
            $seenGroupMemberships[$groupKey] = $true
            $directMembership = Get-DirectGroupMembership -GroupId $finding.SourceGroupId -UserId $finding.UserId
            if ($directMembership.Count -eq 0) {
                $manifest.operations += [pscustomobject]@{
                    Sequence = $sequence
                    OperationType = 'RemoveGroupMember'
                    Status = 'SkippedNestedOrMissing'
                    GroupId = $finding.SourceGroupId
                    GroupDisplayName = $finding.SourceGroupName
                    UserId = $finding.UserId
                    UserPrincipalName = $finding.UserPrincipalName
                    RoleDisplayName = $finding.RoleDisplayName
                    DirectoryScopeId = $finding.DirectoryScopeId
                    FindingSeverity = $finding.Severity
                }
                $sequence++
            }
            else {
                if ($PSCmdlet.ShouldProcess($finding.UserPrincipalName, ("Remove from privileged group {0}" -f $finding.SourceGroupName))) {
                    Invoke-GraphJson -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/members/{1}/`$ref" -f $finding.SourceGroupId, $finding.UserId) -Method 'DELETE' | Out-Null
                    $status = 'Removed'
                }
                else {
                    $status = 'WhatIf'
                }

                $manifest.operations += [pscustomobject]@{
                    Sequence = $sequence
                    OperationType = 'RemoveGroupMember'
                    Status = $status
                    GroupId = $finding.SourceGroupId
                    GroupDisplayName = $finding.SourceGroupName
                    UserId = $finding.UserId
                    UserPrincipalName = $finding.UserPrincipalName
                    RoleDisplayName = $finding.RoleDisplayName
                    DirectoryScopeId = $finding.DirectoryScopeId
                    FindingSeverity = $finding.Severity
                }
                $sequence++
            }
        }
    }

    if ($DisableAccounts -and -not $seenDisabledUsers.ContainsKey($finding.UserId)) {
        $seenDisabledUsers[$finding.UserId] = $true
        $disableResult = Disable-UserAccount -UserId $finding.UserId -UserPrincipalName $finding.UserPrincipalName
        $manifest.operations += [pscustomobject]@{
            Sequence = $sequence
            OperationType = 'DisableUser'
            Status = $disableResult.Action
            UserId = $finding.UserId
            UserPrincipalName = $finding.UserPrincipalName
            PreviousAccountEnabled = [bool]$disableResult.PreviousAccountEnabled
            FindingSeverity = $finding.Severity
        }
        $sequence++
    }
}

$manifestPath = Join-Path $OutputPath 'remediation-manifest.json'
$summaryPath = Join-Path $OutputPath 'remediation-summary.md'

$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath
$summary = @(
    '# Entra Privileged Remediation'
    ''
    ('Tenant: `{0}`' -f $TenantIdOrDomain)
    ('Minimum severity: `{0}`' -f $MinimumSeverity)
    ('Disable accounts: `{0}`' -f [bool]$DisableAccounts)
    ('Candidate findings: `{0}`' -f $candidateFindings.Count)
    ('Recorded operations: `{0}`' -f $manifest.operations.Count)
) -join [Environment]::NewLine
$summary | Set-Content -LiteralPath $summaryPath

Write-Info ("Remediation manifest written to {0}" -f $manifestPath)
Write-Info ("Remediation summary written to {0}" -f $summaryPath)
