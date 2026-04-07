[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$TenantIdOrDomain = 'algono.co',
    [string]$OrgChartPath = '.\prontoso\PhonyOrgChartForSecurityAudit.csv',
    [string]$SeedPlanPath = '.\prontoso\ProntosoTenantSeed.json',
    [string]$OutputPath = '.\artifacts\prontoso-seed',
    [string]$PreferredUserDomain = 'algono.co',
    [string]$InitialPassword,
    [switch]$UseDeviceAuthentication,
    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RequiredScopes = @(
    'Directory.Read.All',
    'User.ReadWrite.All',
    'User.EnableDisableAccount.All',
    'Group.ReadWrite.All',
    'GroupMember.ReadWrite.All',
    'AdministrativeUnit.ReadWrite.All',
    'RoleManagement.ReadWrite.Directory'
)

function Write-Info {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Write-WarnLine {
    param([string]$Message)
    Write-Warning $Message
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
        [hashtable]$Headers,
        [object]$Body
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

function Get-NormalizedKey {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    return $Value.Trim().ToLowerInvariant()
}

function Get-MailNickname {
    param([string]$Value)

    $nickname = ($Value.ToLowerInvariant() -replace '[^a-z0-9-]', '')
    if ([string]::IsNullOrWhiteSpace($nickname)) {
        return ('grp{0}' -f (Get-Random -Minimum 1000 -Maximum 9999))
    }

    if ($nickname.Length -gt 40) {
        return $nickname.Substring(0, 40)
    }

    return $nickname
}

function Get-UserAliasFromDisplayName {
    param([string]$DisplayName)

    $tokens = @($DisplayName -replace '[^A-Za-z0-9 ]', '' -split '\s+' | Where-Object { $_ })
    if ($tokens.Count -ge 2) {
        return ('{0}.{1}' -f $tokens[0], $tokens[$tokens.Count - 1]).ToLowerInvariant()
    }

    if ($tokens.Count -eq 1) {
        return $tokens[0].ToLowerInvariant()
    }

    throw "Unable to generate alias for display name '$DisplayName'."
}

function Convert-DisplayNameToParts {
    param([string]$DisplayName)

    $tokens = @($DisplayName -split '\s+' | Where-Object { $_ })
    if ($tokens.Count -lt 2) {
        return [pscustomobject]@{
            GivenName = $DisplayName
            Surname = 'User'
        }
    }

    [pscustomobject]@{
        GivenName = $tokens[0]
        Surname = $tokens[$tokens.Count - 1]
    }
}

function New-RandomPassword {
    param([int]$Length = 22)

    $alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@$%*?-_'
    $builder = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Length; $i++) {
        [void]$builder.Append($alphabet[(Get-Random -Minimum 0 -Maximum $alphabet.Length)])
    }

    return $builder.ToString()
}

function Load-SeedPlan {
    param([string]$Path)

    $content = Get-Content -LiteralPath $Path -Raw
    $plan = $content | ConvertFrom-Json -Depth 12

    if ($null -eq $plan.users) {
        $plan | Add-Member -NotePropertyName users -NotePropertyValue ([pscustomobject]@{}) -Force
    }

    if ($null -eq $plan.users.defaults) {
        $plan.users | Add-Member -NotePropertyName defaults -NotePropertyValue ([pscustomobject]@{}) -Force
    }

    if ($null -eq $plan.users.overrides) {
        $plan.users | Add-Member -NotePropertyName overrides -NotePropertyValue @() -Force
    }

    if ($null -eq $plan.users.extras) {
        $plan.users | Add-Member -NotePropertyName extras -NotePropertyValue @() -Force
    }

    if ($null -eq $plan.administrativeUnits) {
        $plan | Add-Member -NotePropertyName administrativeUnits -NotePropertyValue @() -Force
    }

    if ($null -eq $plan.groups) {
        $plan | Add-Member -NotePropertyName groups -NotePropertyValue @() -Force
    }

    if ($null -eq $plan.roleAssignments) {
        $plan | Add-Member -NotePropertyName roleAssignments -NotePropertyValue @() -Force
    }

    return $plan
}

function Get-OrganizationInfo {
    $orgs = Invoke-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains'
    if (-not $orgs -or $orgs.Count -eq 0) {
        throw 'Unable to resolve organization details from Microsoft Graph.'
    }

    return $orgs[0]
}

function Resolve-UserDomain {
    param(
        [object]$Organization,
        [string]$PreferredDomain
    )

    $verifiedDomains = @($Organization.verifiedDomains)
    foreach ($domain in $verifiedDomains) {
        if ($domain.name -eq $PreferredDomain) {
            return $domain.name
        }
    }

    $defaultDomain = $verifiedDomains | Where-Object { $_.isDefault } | Select-Object -First 1
    if ($defaultDomain) {
        Write-WarnLine ("Preferred domain '{0}' is not verified in the tenant. Falling back to '{1}'." -f $PreferredDomain, $defaultDomain.name)
        return $defaultDomain.name
    }

    if ($verifiedDomains.Count -gt 0) {
        Write-WarnLine ("Preferred domain '{0}' is not verified in the tenant. Falling back to '{1}'." -f $PreferredDomain, $verifiedDomains[0].name)
        return $verifiedDomains[0].name
    }

    throw 'No verified domains were returned by Microsoft Graph.'
}

function Build-UserSpecs {
    param(
        [object[]]$OrgChartRows,
        [object]$Plan,
        [string]$ResolvedDomain
    )

    $specs = New-Object System.Collections.Generic.List[object]
    $overrideLookup = @{}
    foreach ($override in @($Plan.users.overrides)) {
        $overrideLookup[(Get-NormalizedKey -Value $override.displayName)] = $override
    }

    $defaults = $Plan.users.defaults
    $counter = 1
    foreach ($row in $OrgChartRows) {
        $parts = Convert-DisplayNameToParts -DisplayName $row.Name
        $alias = Get-UserAliasFromDisplayName -DisplayName $row.Name
        $override = $overrideLookup[(Get-NormalizedKey -Value $row.Name)]

        $specs.Add([pscustomobject]@{
                Source = 'OrgChart'
                DisplayName = $row.Name
                GivenName = $parts.GivenName
                Surname = $parts.Surname
                Alias = $alias
                UserPrincipalName = ('{0}@{1}' -f $alias, $ResolvedDomain)
                JobTitle = $row.'Job Title'
                Department = $row.'AU / Department'
                AccountEnabled = if ($null -ne $override -and $null -ne $override.accountEnabled) { [bool]$override.accountEnabled } else { $true }
                CompanyName = if ($defaults.companyName) { $defaults.companyName } else { 'Algono' }
                UsageLocation = if ($defaults.usageLocation) { $defaults.usageLocation } else { 'US' }
                EmployeeId = ('PRONTOSO-{0:d3}' -f $counter)
            })
        $counter++
    }

    foreach ($extra in @($Plan.users.extras)) {
        $parts = if ($extra.givenName -and $extra.surname) {
            [pscustomobject]@{
                GivenName = $extra.givenName
                Surname = $extra.surname
            }
        }
        else {
            Convert-DisplayNameToParts -DisplayName $extra.displayName
        }

        $alias = if ($extra.alias) { $extra.alias.ToLowerInvariant() } else { Get-UserAliasFromDisplayName -DisplayName $extra.displayName }
        $upn = if ($extra.userPrincipalName) { $extra.userPrincipalName } else { '{0}@{1}' -f $alias, $ResolvedDomain }

        $specs.Add([pscustomobject]@{
                Source = 'SeedPlan'
                DisplayName = $extra.displayName
                GivenName = $parts.GivenName
                Surname = $parts.Surname
                Alias = $alias
                UserPrincipalName = $upn
                JobTitle = $extra.jobTitle
                Department = $extra.department
                AccountEnabled = if ($null -ne $extra.accountEnabled) { [bool]$extra.accountEnabled } else { $true }
                CompanyName = if ($extra.companyName) { $extra.companyName } elseif ($defaults.companyName) { $defaults.companyName } else { 'Algono' }
                UsageLocation = if ($extra.usageLocation) { $extra.usageLocation } elseif ($defaults.usageLocation) { $defaults.usageLocation } else { 'US' }
                EmployeeId = if ($extra.employeeId) { $extra.employeeId } else { 'PRONTOSO-EXTRA-{0}' -f $alias.ToUpperInvariant() }
            })
    }

    return @($specs)
}

function Try-GetUserByUpn {
    param([string]$UserPrincipalName)

    $uri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName?`$select=id,displayName,userPrincipalName,department,jobTitle,accountEnabled,companyName,employeeId"
    try {
        return Invoke-GraphJson -Uri $uri
    }
    catch {
        if (Test-GraphNotFound -ErrorRecord $_) {
            return $null
        }

        throw
    }
}

function Ensure-User {
    param(
        [object]$Spec,
        [string]$SharedInitialPassword
    )

    $existing = Try-GetUserByUpn -UserPrincipalName $Spec.UserPrincipalName
    $generatedPassword = $null
    $action = 'Existing'

    if ($null -eq $existing) {
        $generatedPassword = if ($SharedInitialPassword) { $SharedInitialPassword } else { New-RandomPassword }
        $body = @{
            accountEnabled = [bool]$Spec.AccountEnabled
            displayName = $Spec.DisplayName
            mailNickname = (Get-MailNickname -Value $Spec.Alias)
            userPrincipalName = $Spec.UserPrincipalName
            givenName = $Spec.GivenName
            surname = $Spec.Surname
            department = $Spec.Department
            jobTitle = $Spec.JobTitle
            companyName = $Spec.CompanyName
            usageLocation = $Spec.UsageLocation
            employeeId = $Spec.EmployeeId
            passwordProfile = @{
                forceChangePasswordNextSignIn = $true
                password = $generatedPassword
            }
        }

        if ($PSCmdlet.ShouldProcess($Spec.UserPrincipalName, 'Create Entra user')) {
            $existing = Invoke-GraphJson -Uri 'https://graph.microsoft.com/v1.0/users' -Method 'POST' -Body $body
        }

        $action = 'Created'
    }
    else {
        $patch = @{}
        $propertyMap = @{
            department = 'Department'
            jobTitle = 'JobTitle'
            companyName = 'CompanyName'
            employeeId = 'EmployeeId'
        }

        foreach ($graphProperty in $propertyMap.Keys) {
            $desired = $Spec.($propertyMap[$graphProperty])
            $current = $existing.$graphProperty
            if ($desired -and $desired -ne $current) {
                $patch[$graphProperty] = $desired
            }
        }

        if ([bool]$existing.accountEnabled -ne [bool]$Spec.AccountEnabled) {
            $patch.accountEnabled = [bool]$Spec.AccountEnabled
        }

        if ($patch.Count -gt 0 -and $PSCmdlet.ShouldProcess($Spec.UserPrincipalName, 'Update Entra user profile')) {
            Invoke-GraphJson -Uri ("https://graph.microsoft.com/v1.0/users/{0}" -f $existing.id) -Method 'PATCH' -Body $patch | Out-Null
            $existing = Try-GetUserByUpn -UserPrincipalName $Spec.UserPrincipalName
            $action = 'Updated'
        }
    }

    return [pscustomobject]@{
        Alias = $Spec.Alias
        DisplayName = $Spec.DisplayName
        Id = $existing.id
        UserId = $existing.id
        UserPrincipalName = $Spec.UserPrincipalName
        Department = $Spec.Department
        AccountEnabled = [bool]$Spec.AccountEnabled
        Action = $action
        GeneratedPassword = $generatedPassword
    }
}

function Get-OrCreateAdministrativeUnit {
    param([object]$Spec)

    $filter = [Uri]::EscapeDataString(("displayName eq '{0}'" -f (Escape-ODataString -Value $Spec.displayName)))
    $uri = "https://graph.microsoft.com/v1.0/directory/administrativeUnits?`$filter=$filter&`$select=id,displayName,description"
    $existing = @(Invoke-GraphCollection -Uri $uri) | Select-Object -First 1

    if ($existing) {
        return [pscustomobject]@{
            Key = $Spec.key
            Id = $existing.id
            DisplayName = $existing.displayName
            Action = 'Existing'
        }
    }

    $body = @{
        displayName = $Spec.displayName
        description = $Spec.description
    }

    if ($PSCmdlet.ShouldProcess($Spec.displayName, 'Create administrative unit')) {
        $created = Invoke-GraphJson -Uri 'https://graph.microsoft.com/v1.0/directory/administrativeUnits' -Method 'POST' -Body $body
    }
    else {
        $created = [pscustomobject]@{ id = $null; displayName = $Spec.displayName }
    }

    [pscustomobject]@{
        Key = $Spec.key
        Id = $created.id
        DisplayName = $created.displayName
        Action = 'Created'
    }
}

function Add-AdministrativeUnitMember {
    param(
        [string]$AdministrativeUnitId,
        [string]$MemberId,
        [string]$Description
    )

    $body = @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$MemberId"
    }

    if (-not $PSCmdlet.ShouldProcess($Description, 'Add administrative unit member')) {
        return 'WhatIf'
    }

    try {
        Invoke-GraphJson -Uri ("https://graph.microsoft.com/v1.0/directory/administrativeUnits/{0}/members/`$ref" -f $AdministrativeUnitId) -Method 'POST' -Body $body | Out-Null
        return 'Added'
    }
    catch {
        if ([string]$_.Exception.Message -match 'added object references already exist') {
            return 'Existing'
        }

        throw
    }
}

function Get-OrCreateGroup {
    param([object]$Spec)

    $filter = [Uri]::EscapeDataString(("displayName eq '{0}'" -f (Escape-ODataString -Value $Spec.displayName)))
    $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=$filter&`$select=id,displayName,isAssignableToRole"
    $existing = @(Invoke-GraphCollection -Uri $uri) | Select-Object -First 1

    if ($existing) {
        return [pscustomobject]@{
            Key = $Spec.key
            Id = $existing.id
            DisplayName = $existing.displayName
            IsAssignableToRole = [bool]$existing.isAssignableToRole
            Action = 'Existing'
        }
    }

    $body = @{
        displayName = $Spec.displayName
        description = $Spec.description
        mailEnabled = $false
        securityEnabled = $true
        mailNickname = (Get-MailNickname -Value $Spec.key)
        isAssignableToRole = [bool]$Spec.isAssignableToRole
    }

    if ($PSCmdlet.ShouldProcess($Spec.displayName, 'Create group')) {
        $created = Invoke-GraphJson -Uri 'https://graph.microsoft.com/v1.0/groups' -Method 'POST' -Body $body
    }
    else {
        $created = [pscustomobject]@{ id = $null; displayName = $Spec.displayName; isAssignableToRole = [bool]$Spec.isAssignableToRole }
    }

    [pscustomobject]@{
        Key = $Spec.key
        Id = $created.id
        DisplayName = $created.displayName
        IsAssignableToRole = [bool]$created.isAssignableToRole
        Action = 'Created'
    }
}

function Add-GroupMember {
    param(
        [string]$GroupId,
        [string]$MemberId,
        [string]$Description
    )

    $body = @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$MemberId"
    }

    if (-not $PSCmdlet.ShouldProcess($Description, 'Add group member')) {
        return 'WhatIf'
    }

    try {
        Invoke-GraphJson -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/members/`$ref" -f $GroupId) -Method 'POST' -Body $body | Out-Null
        return 'Added'
    }
    catch {
        if ([string]$_.Exception.Message -match 'added object references already exist') {
            return 'Existing'
        }

        throw
    }
}

function Get-RoleDefinitionsByDisplayName {
    $definitions = Invoke-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName'
    $lookup = @{}
    foreach ($definition in $definitions) {
        $lookup[$definition.displayName] = $definition
    }

    return $lookup
}

function Ensure-RoleAssignment {
    param(
        [string]$PrincipalId,
        [string]$RoleDefinitionId,
        [string]$DirectoryScopeId,
        [string]$Description
    )

    $filter = [Uri]::EscapeDataString(("principalId eq '{0}' and roleDefinitionId eq '{1}' and directoryScopeId eq '{2}'" -f $PrincipalId, $RoleDefinitionId, (Escape-ODataString -Value $DirectoryScopeId)))
    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=$filter&`$select=id,principalId,roleDefinitionId,directoryScopeId"
    $existing = @(Invoke-GraphCollection -Uri $uri) | Select-Object -First 1

    if ($existing) {
        return [pscustomobject]@{
            Id = $existing.id
            Action = 'Existing'
        }
    }

    $body = @{
        principalId = $PrincipalId
        roleDefinitionId = $RoleDefinitionId
        directoryScopeId = $DirectoryScopeId
    }

    if ($PSCmdlet.ShouldProcess($Description, 'Create role assignment')) {
        $created = Invoke-GraphJson -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' -Method 'POST' -Body $body
    }
    else {
        $created = [pscustomobject]@{ id = $null }
    }

    [pscustomobject]@{
        Id = $created.id
        Action = 'Created'
    }
}

Ensure-Directory -Path $OutputPath

if (-not (Test-Path -LiteralPath $OrgChartPath)) {
    throw "Org chart file not found: $OrgChartPath"
}

if (-not (Test-Path -LiteralPath $SeedPlanPath)) {
    throw "Seed plan file not found: $SeedPlanPath"
}

if ($ValidateOnly) {
    Write-Info 'ValidateOnly mode enabled. Validating local dependencies only.'
    $null = Import-Csv -LiteralPath $OrgChartPath
    $null = Load-SeedPlan -Path $SeedPlanPath
    Write-Info 'Validation complete.'
    return
}

Ensure-GraphConnection

$orgChartRows = @(Import-Csv -LiteralPath $OrgChartPath)
$seedPlan = Load-SeedPlan -Path $SeedPlanPath
$organization = Get-OrganizationInfo
$resolvedDomain = Resolve-UserDomain -Organization $organization -PreferredDomain $PreferredUserDomain
$userSpecs = Build-UserSpecs -OrgChartRows $orgChartRows -Plan $seedPlan -ResolvedDomain $resolvedDomain

$manifest = [ordered]@{
    generatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    tenant = $TenantIdOrDomain
    tenantDisplayName = $organization.displayName
    resolvedUserDomain = $resolvedDomain
    users = @()
    administrativeUnits = @()
    administrativeUnitMemberships = @()
    groups = @()
    groupMemberships = @()
    roleAssignments = @()
}

$userLookupByAlias = @{}
foreach ($spec in $userSpecs) {
    $userRecord = Ensure-User -Spec $spec -SharedInitialPassword $InitialPassword
    $manifest.users += $userRecord
    $userLookupByAlias[$spec.Alias] = $userRecord
}

$administrativeUnitLookup = @{}
foreach ($auSpec in @($seedPlan.administrativeUnits)) {
    $auRecord = Get-OrCreateAdministrativeUnit -Spec $auSpec
    $manifest.administrativeUnits += $auRecord
    $administrativeUnitLookup[$auSpec.key] = $auRecord
}

foreach ($spec in $userSpecs) {
    if ([string]::IsNullOrWhiteSpace($spec.Department) -or -not $administrativeUnitLookup.ContainsKey($spec.Department)) {
        continue
    }

    $auRecord = $administrativeUnitLookup[$spec.Department]
    $userRecord = $userLookupByAlias[$spec.Alias]
    $membershipAction = Add-AdministrativeUnitMember -AdministrativeUnitId $auRecord.Id -MemberId $userRecord.UserId -Description ("{0} -> {1}" -f $spec.UserPrincipalName, $auRecord.DisplayName)
    $manifest.administrativeUnitMemberships += [pscustomobject]@{
        AdministrativeUnitId = $auRecord.Id
        AdministrativeUnitDisplayName = $auRecord.DisplayName
        UserId = $userRecord.UserId
        UserPrincipalName = $spec.UserPrincipalName
        Action = $membershipAction
    }
}

$groupLookup = @{}
foreach ($groupSpec in @($seedPlan.groups)) {
    $groupRecord = Get-OrCreateGroup -Spec $groupSpec
    $manifest.groups += $groupRecord
    $groupLookup[$groupSpec.key] = $groupRecord

    foreach ($memberAlias in @($groupSpec.members)) {
        if (-not $userLookupByAlias.ContainsKey($memberAlias)) {
            throw "Group member alias '$memberAlias' from seed plan was not created."
        }

        $userRecord = $userLookupByAlias[$memberAlias]
        $membershipAction = Add-GroupMember -GroupId $groupRecord.Id -MemberId $userRecord.UserId -Description ("{0} -> {1}" -f $userRecord.UserPrincipalName, $groupRecord.DisplayName)
        $manifest.groupMemberships += [pscustomobject]@{
            GroupId = $groupRecord.Id
            GroupDisplayName = $groupRecord.DisplayName
            UserId = $userRecord.UserId
            UserPrincipalName = $userRecord.UserPrincipalName
            Action = $membershipAction
        }
    }
}

$roleDefinitions = Get-RoleDefinitionsByDisplayName
foreach ($assignmentSpec in @($seedPlan.roleAssignments)) {
    if (-not $roleDefinitions.ContainsKey($assignmentSpec.roleDisplayName)) {
        throw ("Role definition '{0}' was not found in the tenant." -f $assignmentSpec.roleDisplayName)
    }

    $principalRecord = switch ($assignmentSpec.principalType) {
        'User' {
            if (-not $userLookupByAlias.ContainsKey($assignmentSpec.principal)) {
                throw "User alias '$($assignmentSpec.principal)' was not created."
            }

            $userLookupByAlias[$assignmentSpec.principal]
        }
        'Group' {
            if (-not $groupLookup.ContainsKey($assignmentSpec.principal)) {
                throw "Group key '$($assignmentSpec.principal)' was not created."
            }

            $groupLookup[$assignmentSpec.principal]
        }
        default {
            throw "Unsupported principal type '$($assignmentSpec.principalType)' in role assignment seed plan."
        }
    }

    $directoryScopeId = if ($assignmentSpec.directoryScopeId) {
        $assignmentSpec.directoryScopeId
    }
    elseif ($assignmentSpec.administrativeUnitKey) {
        if (-not $administrativeUnitLookup.ContainsKey($assignmentSpec.administrativeUnitKey)) {
            throw "Administrative unit key '$($assignmentSpec.administrativeUnitKey)' was not created."
        }

        '/administrativeUnits/{0}' -f $administrativeUnitLookup[$assignmentSpec.administrativeUnitKey].Id
    }
    else {
        '/'
    }

    $roleDefinition = $roleDefinitions[$assignmentSpec.roleDisplayName]
    $roleAssignmentRecord = Ensure-RoleAssignment -PrincipalId $principalRecord.Id -RoleDefinitionId $roleDefinition.id -DirectoryScopeId $directoryScopeId -Description ("{0} -> {1}" -f $principalRecord.DisplayName, $assignmentSpec.roleDisplayName)
    $manifest.roleAssignments += [pscustomobject]@{
        RoleAssignmentId = $roleAssignmentRecord.Id
        PrincipalType = $assignmentSpec.principalType
        PrincipalDisplayName = $principalRecord.DisplayName
        PrincipalId = $principalRecord.Id
        RoleDisplayName = $assignmentSpec.roleDisplayName
        RoleDefinitionId = $roleDefinition.id
        DirectoryScopeId = $directoryScopeId
        Action = $roleAssignmentRecord.Action
    }
}

$manifestPath = Join-Path $OutputPath 'seed-manifest.json'
$passwordPath = Join-Path $OutputPath 'created-user-passwords.csv'
$summaryPath = Join-Path $OutputPath 'seed-summary.md'

$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath
$manifest.users |
    Where-Object { $_.GeneratedPassword } |
    Select-Object DisplayName, UserPrincipalName, GeneratedPassword |
    Export-Csv -LiteralPath $passwordPath -NoTypeInformation

$summary = @(
    '# Prontoso Tenant Seed'
    ''
    ('Tenant: `{0}`' -f $TenantIdOrDomain)
    ('Resolved user domain: `{0}`' -f $resolvedDomain)
    ('Users processed: `{0}`' -f $manifest.users.Count)
    ('Administrative units processed: `{0}`' -f $manifest.administrativeUnits.Count)
    ('Groups processed: `{0}`' -f $manifest.groups.Count)
    ('Role assignments processed: `{0}`' -f $manifest.roleAssignments.Count)
) -join [Environment]::NewLine
$summary | Set-Content -LiteralPath $summaryPath

Write-Info ("Seed manifest written to {0}" -f $manifestPath)
Write-Info ("Created-user password export written to {0}" -f $passwordPath)
Write-Info ("Seed summary written to {0}" -f $summaryPath)
