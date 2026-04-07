[CmdletBinding()]
param(
    [string]$TenantIdOrDomain = 'algono.co',
    [string]$OrgChartPath = '.\prontoso\PhonyOrgChartForSecurityAudit.csv',
    [string]$ExceptionPath = '.\prontoso\PrivilegedAccessExceptions.json',
    [string]$OutputPath = '.\artifacts\entra-privileged-scan',
    [int]$InactiveDays = 45,
    [int]$NewAccountGraceDays = 14,
    [string[]]$AdminDepartments = @('IT_Operations', 'Executive_Floor'),
    [switch]$IncludeEligibleAssignments,
    [switch]$UseDeviceAuthentication,
    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RequiredScopes = @(
    'User.Read.All',
    'AuditLog.Read.All',
    'RoleManagement.Read.Directory',
    'GroupMember.Read.All'
)

$CuratedPrivilegedRoles = @(
    'Global Administrator',
    'Privileged Role Administrator',
    'Privileged Authentication Administrator',
    'Authentication Administrator',
    'Conditional Access Administrator',
    'Security Administrator',
    'Cloud Application Administrator',
    'Application Administrator',
    'Exchange Administrator',
    'SharePoint Administrator',
    'Teams Administrator',
    'Intune Administrator',
    'User Administrator',
    'Password Administrator',
    'Directory Writers',
    'Hybrid Identity Administrator',
    'Helpdesk Administrator'
)

function Write-Info {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Write-WarnLine {
    param([string]$Message)
    Write-Warning $Message
}

function Test-RoleManagementPremiumError {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $message = (($ErrorRecord | Out-String) + [string]$ErrorRecord.Exception.Message)
    return $message -match 'AadPremiumLicenseRequired' -or $message -match 'Entra ID P2' -or $message -match 'ID Governance license'
}

function Get-DateOrNull {
    param([object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    return [DateTimeOffset]::Parse([string]$Value)
}

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-NormalizedLookupKey {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    return $Value.Trim().ToLowerInvariant()
}

function Get-OptionalPropertyValue {
    param(
        [object]$Object,
        [string]$PropertyName,
        $Default = $null
    )

    if ($null -eq $Object) {
        return $Default
    }

    $property = $Object.PSObject.Properties[$PropertyName]
    if ($property) {
        return $property.Value
    }

    return $Default
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

        $nextLinkProperty = $response.PSObject.Properties['@odata.nextLink']
        $nextUri = if ($nextLinkProperty) { [string]$nextLinkProperty.Value } else { $null }
    }

    return $results.ToArray()
}

function Try-GetUsers {
    $baseSelect = 'id,displayName,userPrincipalName,accountEnabled,createdDateTime,userType,department,jobTitle,employeeId,companyName,onPremisesSyncEnabled'
    $candidates = @(
        [pscustomobject]@{
            Label = 'v1.0-with-signInActivity'
            Uri = "https://graph.microsoft.com/v1.0/users?`$select=$baseSelect,signInActivity"
        },
        [pscustomobject]@{
            Label = 'beta-with-signInActivity'
            Uri = "https://graph.microsoft.com/beta/users?`$select=$baseSelect,signInActivity"
        },
        [pscustomobject]@{
            Label = 'v1.0-without-signInActivity'
            Uri = "https://graph.microsoft.com/v1.0/users?`$select=$baseSelect"
        }
    )

    foreach ($candidate in $candidates) {
        try {
            Write-Info ("Collecting users via {0}" -f $candidate.Label)
            return [pscustomobject]@{
                Source = $candidate.Label
                Users = Invoke-GraphCollection -Uri $candidate.Uri
            }
        }
        catch {
            Write-WarnLine ("User collection failed via {0}: {1}" -f $candidate.Label, $_.Exception.Message)
        }
    }

    throw 'Unable to collect users from Microsoft Graph.'
}

function Get-RoleDefinitions {
    $betaUri = 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn,isPrivileged'
    $v1Uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn'

    try {
        Write-Info 'Collecting role definitions via beta to use isPrivileged when available.'
        $definitions = Invoke-GraphCollection -Uri $betaUri
        foreach ($definition in $definitions) {
            $definition | Add-Member -NotePropertyName RiskSource -NotePropertyValue 'beta.isPrivileged' -Force
        }

        return @($definitions)
    }
    catch {
        Write-WarnLine ("Falling back to v1.0 role definitions: {0}" -f $_.Exception.Message)
        $definitions = Invoke-GraphCollection -Uri $v1Uri

        foreach ($definition in $definitions) {
            $isCurated = $definition.displayName -in $CuratedPrivilegedRoles -or $definition.displayName -match 'Administrator'
            $definition | Add-Member -NotePropertyName isPrivileged -NotePropertyValue $isCurated -Force
            $definition | Add-Member -NotePropertyName RiskSource -NotePropertyValue 'curated-name-match' -Force
        }

        return @($definitions)
    }
}

function Get-RoleAssignments {
    param(
        [string]$AssignmentKind,
        [object[]]$RoleDefinitions
    )

    $uri = switch ($AssignmentKind) {
        'Active' {
            'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$select=id,principalId,roleDefinitionId,directoryScopeId,assignmentType,memberType,startDateTime,endDateTime'
        }
        'Eligible' {
            'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$select=id,principalId,roleDefinitionId,directoryScopeId,memberType,startDateTime,endDateTime'
        }
        default {
            throw "Unsupported assignment kind '$AssignmentKind'."
        }
    }

    try {
        $items = Invoke-GraphCollection -Uri $uri
    }
    catch {
        if ($AssignmentKind -eq 'Active' -and (Test-RoleManagementPremiumError -ErrorRecord $_)) {
            Write-WarnLine 'Modern role schedule APIs require Entra ID P2 in this tenant. Falling back to legacy directory role membership for active assignments.'
            return Get-LegacyRoleAssignments -RoleDefinitions $RoleDefinitions
        }

        if ($AssignmentKind -eq 'Eligible' -and (Test-RoleManagementPremiumError -ErrorRecord $_)) {
            Write-WarnLine 'Eligible role inventory requires Entra ID P2 in this tenant. Skipping eligible assignments.'
            return @()
        }

        throw
    }

    foreach ($item in $items) {
        $item | Add-Member -NotePropertyName AssignmentState -NotePropertyValue $AssignmentKind -Force
    }

    return @($items)
}

function Get-LegacyRoleAssignments {
    param([object[]]$RoleDefinitions)

    $roleDefinitionByTemplateId = @{}
    $roleDefinitionByDisplayName = @{}
    foreach ($roleDefinition in $RoleDefinitions) {
        if ($roleDefinition.templateId) {
            $roleDefinitionByTemplateId[$roleDefinition.templateId] = $roleDefinition
        }

        $roleDefinitionByDisplayName[$roleDefinition.displayName] = $roleDefinition
    }

    $directoryRoles = Invoke-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName,roleTemplateId'
    $items = New-Object System.Collections.Generic.List[object]

    foreach ($directoryRole in $directoryRoles) {
        $roleDefinition = $null
        if ($directoryRole.roleTemplateId -and $roleDefinitionByTemplateId.ContainsKey($directoryRole.roleTemplateId)) {
            $roleDefinition = $roleDefinitionByTemplateId[$directoryRole.roleTemplateId]
        }
        elseif ($roleDefinitionByDisplayName.ContainsKey($directoryRole.displayName)) {
            $roleDefinition = $roleDefinitionByDisplayName[$directoryRole.displayName]
        }

        if ($null -eq $roleDefinition) {
            Write-WarnLine ("Unable to resolve legacy directory role '{0}' to a role definition." -f $directoryRole.displayName)
            continue
        }

        $members = Invoke-GraphCollection -Uri ("https://graph.microsoft.com/v1.0/directoryRoles/{0}/members?`$select=id,displayName,userPrincipalName" -f $directoryRole.id)
        foreach ($member in $members) {
            $items.Add([pscustomobject]@{
                    id = ('legacy-{0}-{1}' -f $directoryRole.id, $member.id)
                    principalId = $member.id
                    roleDefinitionId = $roleDefinition.id
                    directoryScopeId = '/'
                    assignmentType = 'Assigned'
                    memberType = 'Direct'
                    startDateTime = $null
                    endDateTime = $null
                    AssignmentState = 'Active'
                    LegacyRoleId = $directoryRole.id
                    LegacyRoleDisplayName = $directoryRole.displayName
                })
        }
    }

    return $items.ToArray()
}

function Load-OrgChart {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-WarnLine ("Org chart file not found at {0}. Department-based heuristics will rely on Entra fields only." -f $Path)
        return @{}
    }

    $map = @{}
    foreach ($row in (Import-Csv -LiteralPath $Path)) {
        $map[$row.Name.Trim().ToLowerInvariant()] = $row
    }

    return $map
}

function Load-Exceptions {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-WarnLine ("Exception file not found at {0}. All privilege exceptions will require review until you create it." -f $Path)
        return [pscustomobject]@{
            exceptions = @()
        }
    }

    $content = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($content)) {
        return [pscustomobject]@{
            exceptions = @()
        }
    }

    $parsed = $content | ConvertFrom-Json -Depth 8
    if ($null -eq $parsed.exceptions) {
        $parsed | Add-Member -NotePropertyName exceptions -NotePropertyValue @() -Force
    }

    return $parsed
}

function Get-GroupInfo {
    param(
        [string]$GroupId,
        [hashtable]$Cache
    )

    if ($Cache.ContainsKey($GroupId)) {
        return $Cache[$GroupId]
    }

    $uri = "https://graph.microsoft.com/v1.0/groups/${GroupId}?`$select=id,displayName,mailEnabled,securityEnabled,isAssignableToRole"
    $group = Invoke-GraphJson -Uri $uri
    $Cache[$GroupId] = $group
    return $group
}

function Get-GroupMembers {
    param(
        [string]$GroupId,
        [hashtable]$Cache
    )

    if ($Cache.ContainsKey($GroupId)) {
        return @($Cache[$GroupId])
    }

    $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$count=true&`$select=id,displayName,userPrincipalName,accountEnabled"
    $members = Invoke-GraphCollection -Uri $uri -Headers @{ ConsistencyLevel = 'eventual' }
    $Cache[$GroupId] = @($members)
    return @($members)
}

function Get-ExceptionMatch {
    param(
        [object[]]$Exceptions,
        [pscustomobject]$Record
    )

    foreach ($exception in $Exceptions) {
        $match = $exception.match
        if ($null -eq $match) {
            continue
        }

        $matchUserPrincipalName = Get-OptionalPropertyValue -Object $match -PropertyName 'userPrincipalName'
        $matchDisplayName = Get-OptionalPropertyValue -Object $match -PropertyName 'displayName'
        $matchRoleDisplayName = Get-OptionalPropertyValue -Object $match -PropertyName 'roleDisplayName'
        $matchAssignmentState = Get-OptionalPropertyValue -Object $match -PropertyName 'assignmentState'
        $matchSourceGroupName = Get-OptionalPropertyValue -Object $match -PropertyName 'sourceGroupName'

        if ($matchUserPrincipalName -and ($matchUserPrincipalName -ne $Record.UserPrincipalName)) {
            continue
        }

        if ($matchDisplayName -and ($matchDisplayName -ne $Record.DisplayName)) {
            continue
        }

        if ($matchRoleDisplayName -and ($matchRoleDisplayName -ne $Record.RoleDisplayName)) {
            continue
        }

        if ($matchAssignmentState -and ($matchAssignmentState -ne $Record.AssignmentState)) {
            continue
        }

        if ($matchSourceGroupName -and ($matchSourceGroupName -ne $Record.SourceGroupName)) {
            continue
        }

        return $exception
    }

    return $null
}

function Get-ReviewState {
    param(
        [pscustomobject]$Record,
        [object]$Exception
    )

    if ($null -eq $Exception) {
        return 'ReviewRequired'
    }

    $expiresOn = Get-DateOrNull -Value $Exception.expiresOn
    if ($null -ne $expiresOn -and $expiresOn -lt [DateTimeOffset]::UtcNow) {
        return 'ExceptionExpired'
    }

    return 'ExceptionApproved'
}

function Get-SeverityFromScore {
    param([int]$Score)

    if ($Score -ge 90) { return 'Critical' }
    if ($Score -ge 65) { return 'High' }
    if ($Score -ge 40) { return 'Medium' }
    return 'Low'
}

function Get-StableFindingId {
    param([string[]]$Parts)

    $normalized = (($Parts | ForEach-Object {
                if ([string]::IsNullOrWhiteSpace([string]$_)) {
                    '<null>'
                }
                else {
                    ([string]$_).Trim().ToLowerInvariant()
                }
            }) -join '|')

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($bytes)
    }
    finally {
        $sha256.Dispose()
    }

    $hashText = -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
    return "finding-$hashText"
}

function New-FindingRecord {
    param(
        [object]$User,
        [object]$Role,
        [object]$Assignment,
        [string]$AccessPath,
        [string]$SourceGroupId,
        [string]$SourceGroupName,
        [object]$OrgChartRow,
        [object]$Exception
    )

    $now = [DateTimeOffset]::UtcNow
    $createdDate = Get-DateOrNull -Value $User.createdDateTime
    $lastSuccessful = $null
    $signInActivityProperty = $User.PSObject.Properties['signInActivity']
    if ($signInActivityProperty -and $null -ne $signInActivityProperty.Value) {
        $lastSuccessful = Get-DateOrNull -Value $signInActivityProperty.Value.lastSuccessfulSignInDateTime
    }

    $daysSinceSignIn = if ($lastSuccessful) {
        [math]::Floor(($now - $lastSuccessful).TotalDays)
    }
    else {
        $null
    }

    $orgDepartment = if ($null -ne $OrgChartRow) { $OrgChartRow.'AU / Department' } else { $null }
    $orgTitle = if ($null -ne $OrgChartRow) { $OrgChartRow.'Job Title' } else { $null }
    $department = if ($User.department) { $User.department } elseif ($orgDepartment) { $orgDepartment } else { $null }
    $jobTitle = if ($User.jobTitle) { $User.jobTitle } elseif ($orgTitle) { $orgTitle } else { $null }

    $score = 0
    $signals = New-Object System.Collections.Generic.List[string]

    if ($Role.isPrivileged) {
        $score += 45
        $signals.Add('PrivilegedRole')
    }
    else {
        $score += 20
        $signals.Add('ElevatedRole')
    }

    if ($Assignment.AssignmentState -eq 'Active') {
        $score += 20
        $signals.Add('ActiveAssignment')
    }
    else {
        $score += 8
        $signals.Add('EligibleAssignment')
    }

    if (-not $User.accountEnabled) {
        $score += 40
        $signals.Add('DisabledAccountStillPrivileged')
    }

    if ($User.userType -eq 'Guest') {
        $score += 20
        $signals.Add('GuestAccount')
    }

    if ($null -eq $createdDate -or ($now - $createdDate).TotalDays -ge $NewAccountGraceDays) {
        if ($null -eq $lastSuccessful) {
            $score += 25
            $signals.Add('NoSuccessfulSignIn')
        }
        elseif ($daysSinceSignIn -ge $InactiveDays) {
            $score += 25
            $signals.Add(("Inactive{0}d" -f $InactiveDays))
        }
    }

    if ([string]::IsNullOrWhiteSpace($department)) {
        $score += 10
        $signals.Add('NoDepartmentContext')
    }
    elseif ($department -notin $AdminDepartments) {
        $score += 15
        $signals.Add('NonAdminDepartment')
    }

    if ($null -eq $OrgChartRow) {
        $score += 10
        $signals.Add('MissingFromOrgChart')
    }

    if ($AccessPath -eq 'Group') {
        $score += 5
        $signals.Add('GroupInheritedPrivilege')
    }

    $record = [pscustomobject]@{
        FindingId = Get-StableFindingId -Parts @(
            $User.id,
            $User.userPrincipalName,
            $Role.id,
            $Assignment.AssignmentState,
            $AccessPath,
            $SourceGroupId,
            $Assignment.directoryScopeId,
            (Get-OptionalPropertyValue -Object $Assignment -PropertyName 'LegacyRoleId')
        )
        UserId = $User.id
        DisplayName = $User.displayName
        UserPrincipalName = $User.userPrincipalName
        AccountEnabled = [bool]$User.accountEnabled
        UserType = $User.userType
        Department = $department
        JobTitle = $jobTitle
        CreatedDateTime = if ($createdDate) { $createdDate.UtcDateTime.ToString('o') } else { $null }
        LastSuccessfulSignInDateTime = if ($lastSuccessful) { $lastSuccessful.UtcDateTime.ToString('o') } else { $null }
        DaysSinceLastSuccessfulSignIn = $daysSinceSignIn
        AssignmentInstanceId = $Assignment.id
        AssignmentState = $Assignment.AssignmentState
        AssignmentPrincipalId = $Assignment.principalId
        AccessPath = $AccessPath
        SourceGroupId = $SourceGroupId
        SourceGroupName = $SourceGroupName
        RoleDefinitionId = $Role.id
        RoleDisplayName = $Role.displayName
        RoleRiskSource = $Role.RiskSource
        IsPrivilegedRole = [bool]$Role.isPrivileged
        DirectoryScopeId = $Assignment.directoryScopeId
        AssignmentStartDateTime = $Assignment.startDateTime
        AssignmentEndDateTime = $Assignment.endDateTime
        LegacyRoleId = (Get-OptionalPropertyValue -Object $Assignment -PropertyName 'LegacyRoleId')
        LegacyRoleDisplayName = (Get-OptionalPropertyValue -Object $Assignment -PropertyName 'LegacyRoleDisplayName')
        Signals = @($signals)
        RiskScore = $score
        Severity = $null
        ReviewState = $null
        ExceptionReason = $null
        ExceptionExpiresOn = $null
        ExceptionApprovedBy = $null
        OrgChartDepartment = $orgDepartment
        OrgChartReportsTo = if ($null -ne $OrgChartRow) { $OrgChartRow.'Reports To' } else { $null }
    }

    $record.Severity = Get-SeverityFromScore -Score $record.RiskScore
    $record.ReviewState = Get-ReviewState -Record $record -Exception $Exception

    if ($record.ReviewState -eq 'ExceptionApproved') {
        $record.RiskScore = [Math]::Max(5, $record.RiskScore - 40)
        $record.Severity = Get-SeverityFromScore -Score $record.RiskScore
        $record.ExceptionReason = $Exception.reason
        $record.ExceptionExpiresOn = $Exception.expiresOn
        $record.ExceptionApprovedBy = $Exception.approvedBy
    }
    elseif ($record.ReviewState -eq 'ExceptionExpired') {
        $record.RiskScore += 10
        $record.Severity = Get-SeverityFromScore -Score $record.RiskScore
        $record.ExceptionReason = $Exception.reason
        $record.ExceptionExpiresOn = $Exception.expiresOn
        $record.ExceptionApprovedBy = $Exception.approvedBy
        $record.Signals = @($record.Signals + 'ExpiredException')
    }

    return $record
}

function New-MarkdownSummary {
    param(
        [object[]]$Inventory,
        [object[]]$Findings,
        [string]$Tenant,
        [string]$CollectedUserSource
    )

    $severityCounts = $Findings | Group-Object Severity | Sort-Object Name
    $reviewCounts = $Findings | Group-Object ReviewState | Sort-Object Name
    $topFindings = $Findings |
        Sort-Object -Property @(
            @{ Expression = 'RiskScore'; Descending = $true },
            @{ Expression = 'DisplayName'; Descending = $false }
        ) |
        Select-Object -First 15

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# Entra Privileged Access Scan")
    $lines.Add('')
    $lines.Add(('Tenant: `{0}`' -f $Tenant))
    $lines.Add(('Generated: `{0}`' -f ([DateTimeOffset]::UtcNow.ToString('u'))))
    $lines.Add(('User collection source: `{0}`' -f $CollectedUserSource))
    $lines.Add(('Total privileged inventory rows: `{0}`' -f $Inventory.Count))
    $lines.Add(('Review findings: `{0}`' -f $Findings.Count))
    $lines.Add('')
    $lines.Add('## Severity')
    $lines.Add('')

    foreach ($group in $severityCounts) {
        $lines.Add(("- `{0}`: {1}" -f $group.Name, $group.Count))
    }

    $lines.Add('')
    $lines.Add('## Review State')
    $lines.Add('')

    foreach ($group in $reviewCounts) {
        $lines.Add(("- `{0}`: {1}" -f $group.Name, $group.Count))
    }

    $lines.Add('')
    $lines.Add('## Highest Risk Findings')
    $lines.Add('')
    $lines.Add('| Score | Severity | User | Role | State | Dept | Notes |')
    $lines.Add('| --- | --- | --- | --- | --- | --- | --- |')

    foreach ($finding in $topFindings) {
        $notes = ($finding.Signals -join ', ')
        $lines.Add(("| {0} | {1} | {2} | {3} | {4} | {5} | {6} |" -f
                $finding.RiskScore,
                $finding.Severity,
                $finding.UserPrincipalName,
                $finding.RoleDisplayName,
                $finding.AssignmentState,
                ([string]$finding.Department),
                $notes))
    }

    return ($lines -join [Environment]::NewLine)
}

Ensure-Directory -Path $OutputPath

if ($ValidateOnly) {
    Write-Info 'ValidateOnly mode enabled. Validating local file dependencies only.'
    if (-not (Test-Path -LiteralPath $OrgChartPath)) {
        Write-WarnLine ("Org chart missing: {0}" -f $OrgChartPath)
    }

    if (-not (Test-Path -LiteralPath $ExceptionPath)) {
        Write-WarnLine ("Exception file missing: {0}" -f $ExceptionPath)
    }

    Write-Info 'Validation complete.'
    return
}

Ensure-GraphConnection

$orgChart = Load-OrgChart -Path $OrgChartPath
$exceptions = Load-Exceptions -Path $ExceptionPath
$roleDefinitions = Get-RoleDefinitions
$roleLookup = @{}
foreach ($roleDefinition in $roleDefinitions) {
    $roleLookup[$roleDefinition.id] = $roleDefinition
}

$activeAssignments = Get-RoleAssignments -AssignmentKind 'Active' -RoleDefinitions $roleDefinitions
$eligibleAssignments = if ($IncludeEligibleAssignments) {
    Get-RoleAssignments -AssignmentKind 'Eligible' -RoleDefinitions $roleDefinitions
}
else {
    @()
}

$userCollection = Try-GetUsers
$userLookup = @{}
foreach ($user in $userCollection.Users) {
    $userLookup[$user.id] = $user
}

$groupInfoCache = @{}
$groupMemberCache = @{}
$inventory = New-Object System.Collections.Generic.List[object]

$assignmentSets = @($activeAssignments + $eligibleAssignments)
foreach ($assignment in $assignmentSets) {
    $role = $roleLookup[$assignment.roleDefinitionId]
    if ($null -eq $role) {
        Write-WarnLine ("Role definition not found for assignment roleDefinitionId={0}" -f $assignment.roleDefinitionId)
        continue
    }

    if ($userLookup.ContainsKey($assignment.principalId)) {
        $user = $userLookup[$assignment.principalId]
        $orgRow = $orgChart[(Get-NormalizedLookupKey -Value $user.displayName)]
        $placeholder = [pscustomobject]@{
            UserPrincipalName = $user.userPrincipalName
            DisplayName = $user.displayName
            RoleDisplayName = $role.displayName
            AssignmentState = $assignment.AssignmentState
            SourceGroupName = $null
        }
        $exception = Get-ExceptionMatch -Exceptions $exceptions.exceptions -Record $placeholder
        $inventory.Add((New-FindingRecord -User $user -Role $role -Assignment $assignment -AccessPath 'Direct' -SourceGroupId $null -SourceGroupName $null -OrgChartRow $orgRow -Exception $exception))
        continue
    }

    try {
        $group = Get-GroupInfo -GroupId $assignment.principalId -Cache $groupInfoCache
        $groupMembers = Get-GroupMembers -GroupId $group.id -Cache $groupMemberCache

        foreach ($member in $groupMembers) {
            if (-not $userLookup.ContainsKey($member.id)) {
                continue
            }

            $user = $userLookup[$member.id]
            $orgRow = $orgChart[(Get-NormalizedLookupKey -Value $user.displayName)]
            $placeholder = [pscustomobject]@{
                UserPrincipalName = $user.userPrincipalName
                DisplayName = $user.displayName
                RoleDisplayName = $role.displayName
                AssignmentState = $assignment.AssignmentState
                SourceGroupName = $group.displayName
            }
            $exception = Get-ExceptionMatch -Exceptions $exceptions.exceptions -Record $placeholder
            $inventory.Add((New-FindingRecord -User $user -Role $role -Assignment $assignment -AccessPath 'Group' -SourceGroupId $group.id -SourceGroupName $group.displayName -OrgChartRow $orgRow -Exception $exception))
        }
    }
    catch {
        Write-WarnLine ("Unable to expand principal {0} as a group: {1}" -f $assignment.principalId, $_.Exception.Message)
    }
}

$inventoryRows = @($inventory | Sort-Object -Property @(
        @{ Expression = 'RiskScore'; Descending = $true },
        @{ Expression = 'UserPrincipalName'; Descending = $false },
        @{ Expression = 'RoleDisplayName'; Descending = $false }
    ))
$findings = @($inventoryRows | Where-Object {
        $_.ReviewState -ne 'ExceptionApproved' -or
        $_.Severity -in @('Critical', 'High', 'Medium')
    })

$inventoryJsonPath = Join-Path $OutputPath 'privileged-access-inventory.json'
$findingsJsonPath = Join-Path $OutputPath 'review-findings.json'
$findingsCsvPath = Join-Path $OutputPath 'review-findings.csv'
$summaryPath = Join-Path $OutputPath 'summary.md'

$inventoryRows | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $inventoryJsonPath
$findings | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $findingsJsonPath
$findings | Export-Csv -LiteralPath $findingsCsvPath -NoTypeInformation
(New-MarkdownSummary -Inventory $inventoryRows -Findings $findings -Tenant $TenantIdOrDomain -CollectedUserSource $userCollection.Source) | Set-Content -LiteralPath $summaryPath

Write-Info ("Inventory rows written to {0}" -f $inventoryJsonPath)
Write-Info ("Findings JSON written to {0}" -f $findingsJsonPath)
Write-Info ("Findings CSV written to {0}" -f $findingsCsvPath)
Write-Info ("Summary written to {0}" -f $summaryPath)
