[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Interactive')]
param(
    [string]$TenantIdOrDomain = 'algono.co',
    [string]$FindingsPath = '.\artifacts\entra-privileged-scan\review-findings.json',
    [string]$OutputPath = '.\artifacts\entra-privileged-remediation',
    [ValidateSet('Critical', 'High', 'Medium', 'Low')]
    [string]$MinimumSeverity = 'High',
    [switch]$DisableAccounts,
    [Parameter(ParameterSetName = 'Rollback', Mandatory = $true)]
    [string]$RollbackManifestPath,
    [switch]$UseDeviceAuthentication,
    [switch]$ValidateOnly,
    [switch]$ValidateOnline,
    [Parameter(ParameterSetName = 'Interactive')]
    [switch]$Interactive,
    [Parameter(ParameterSetName = 'Interactive')]
    [string]$InteractiveRulesCsvPath = '.\prontoso\rules.csv',
    [Parameter(ParameterSetName = 'Csv', Mandatory = $true)]
    [string]$RulesCsv,
    [Parameter(ParameterSetName = 'Json', Mandatory = $true)]
    [string]$RulesJson,
    [string]$RulesNormalizedPath,
    [Parameter(ParameterSetName = 'Interactive')]
    [switch]$UseConsoleGui
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RequiredScopes = @(
    'RoleManagement.ReadWrite.Directory',
    'GroupMember.ReadWrite.All',
    'User.Read.All',
    'User.EnableDisableAccount.All'
)

$ValidationScopes = @(
    'User.Read.All',
    'GroupMember.Read.All',
    'RoleManagement.Read.Directory'
)

$SeverityRank = @{
    Low = 1
    Medium = 2
    High = 3
    Critical = 4
}

$AllowedRuleModes = @('Allow', 'Deny')
$AllowedRuleActions = @('Keep', 'Ignore', 'Remove', 'Disable')
$RuleExportColumns = @(
    'RuleId',
    'Enabled',
    'Mode',
    'Action',
    'FindingId',
    'UserPrincipalName',
    'DisplayName',
    'RoleDisplayName',
    'AssignmentState',
    'SourceGroupName',
    'AccessPath',
    'DirectoryScopeId',
    'SeverityFloor',
    'Reason',
    'ApprovedBy',
    'TicketId',
    'ExpiresOn'
)

$CurrentActorUpn = $null

function Write-Info {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Write-WarnLine {
    param([string]$Message)
    Write-Warning $Message
}

function Initialize-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Initialize-ParentDirectory {
    param([string]$Path)

    $parent = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        Initialize-Directory -Path $parent
    }
}

function Write-FileUtf8 {
    param(
        [string]$Path,
        [string]$Content
    )

    Initialize-ParentDirectory -Path $Path
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Get-DateOrNull {
    param([object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    return [DateTimeOffset]::Parse([string]$Value)
}

function Get-NormalizedLookupKey {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    return $Value.Trim().ToLowerInvariant()
}

function ConvertTo-BooleanValue {
    param(
        [object]$Value,
        [bool]$Default = $false
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $Default
    }

    if ($Value -is [bool]) {
        return [bool]$Value
    }

    switch -Regex (([string]$Value).Trim().ToLowerInvariant()) {
        '^(1|true|yes|y)$' { return $true }
        '^(0|false|no|n)$' { return $false }
        default { throw "Unable to parse boolean value '$Value'." }
    }
}

function Get-StableFindingId {
    param(
        [string]$UserId,
        [string]$UserPrincipalName,
        [string]$RoleDefinitionId,
        [string]$AssignmentState,
        [string]$AccessPath,
        [string]$SourceGroupId,
        [string]$DirectoryScopeId,
        [string]$LegacyRoleId
    )

    $parts = @(
        $UserId,
        $UserPrincipalName,
        $RoleDefinitionId,
        $AssignmentState,
        $AccessPath,
        $SourceGroupId,
        $DirectoryScopeId,
        $LegacyRoleId
    )

    $normalized = (($parts | ForEach-Object {
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

function Initialize-FindingShape {
    param([object[]]$Findings)

    $normalized = New-Object System.Collections.Generic.List[object]

    foreach ($finding in @($Findings)) {
        $findingId = if ($finding.PSObject.Properties['FindingId'] -and -not [string]::IsNullOrWhiteSpace([string]$finding.FindingId)) {
            [string]$finding.FindingId
        }
        else {
            Get-StableFindingId `
                -UserId ([string]$finding.UserId) `
                -UserPrincipalName ([string]$finding.UserPrincipalName) `
                -RoleDefinitionId ([string]$finding.RoleDefinitionId) `
                -AssignmentState ([string]$finding.AssignmentState) `
                -AccessPath ([string]$finding.AccessPath) `
                -SourceGroupId ([string]$finding.SourceGroupId) `
                -DirectoryScopeId ([string]$finding.DirectoryScopeId) `
                -LegacyRoleId ([string]$finding.LegacyRoleId)
        }

        if (-not $finding.PSObject.Properties['FindingId']) {
            $finding | Add-Member -NotePropertyName FindingId -NotePropertyValue $findingId -Force
        }
        else {
            $finding.FindingId = $findingId
        }

        $normalized.Add($finding)
    }

    return $normalized.ToArray()
}

function Get-RuleTemplateCsvContent {
    return ($RuleExportColumns -join ',')
}

function Initialize-RulesCsvTemplate {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Info ("Rules CSV not found at {0}. Creating a template." -f $Path)
        Write-FileUtf8 -Path $Path -Content (Get-RuleTemplateCsvContent)
    }
}

function Get-NextRuleId {
    param([object[]]$ExistingRules)

    $maxSequence = 0
    foreach ($rule in @($ExistingRules)) {
        $ruleId = [string]$rule.RuleId
        if ($ruleId -match '^RULE-(\d+)$') {
            $maxSequence = [Math]::Max($maxSequence, [int]$Matches[1])
        }
    }

    return ('RULE-{0:d4}' -f ($maxSequence + 1))
}

function New-NormalizedRule {
    param(
        [object]$Rule,
        [int]$Order,
        [string]$SourceLabel
    )

    $mode = if ([string]::IsNullOrWhiteSpace([string]$Rule.Mode)) { 'Allow' } else { ([string]$Rule.Mode).Trim() }
    $action = if ([string]::IsNullOrWhiteSpace([string]$Rule.Action)) {
        if ($mode -eq 'Deny') { 'Remove' } else { 'Keep' }
    }
    else {
        ([string]$Rule.Action).Trim()
    }

    $enabled = ConvertTo-BooleanValue -Value $Rule.Enabled -Default $true
    $expiresOnValue = Get-DateOrNull -Value $Rule.ExpiresOn
    $severityFloor = if ([string]::IsNullOrWhiteSpace([string]$Rule.SeverityFloor)) { $null } else { ([string]$Rule.SeverityFloor).Trim() }

    [pscustomobject]@{
        RuleId = if ([string]::IsNullOrWhiteSpace([string]$Rule.RuleId)) { ('RULE-{0:d4}' -f $Order) } else { ([string]$Rule.RuleId).Trim() }
        Enabled = $enabled
        Mode = $mode
        Action = $action
        FindingId = if ([string]::IsNullOrWhiteSpace([string]$Rule.FindingId)) { $null } else { ([string]$Rule.FindingId).Trim() }
        UserPrincipalName = if ([string]::IsNullOrWhiteSpace([string]$Rule.UserPrincipalName)) { $null } else { ([string]$Rule.UserPrincipalName).Trim() }
        DisplayName = if ([string]::IsNullOrWhiteSpace([string]$Rule.DisplayName)) { $null } else { ([string]$Rule.DisplayName).Trim() }
        RoleDisplayName = if ([string]::IsNullOrWhiteSpace([string]$Rule.RoleDisplayName)) { $null } else { ([string]$Rule.RoleDisplayName).Trim() }
        AssignmentState = if ([string]::IsNullOrWhiteSpace([string]$Rule.AssignmentState)) { $null } else { ([string]$Rule.AssignmentState).Trim() }
        SourceGroupName = if ([string]::IsNullOrWhiteSpace([string]$Rule.SourceGroupName)) { $null } else { ([string]$Rule.SourceGroupName).Trim() }
        AccessPath = if ([string]::IsNullOrWhiteSpace([string]$Rule.AccessPath)) { $null } else { ([string]$Rule.AccessPath).Trim() }
        DirectoryScopeId = if ([string]::IsNullOrWhiteSpace([string]$Rule.DirectoryScopeId)) { $null } else { ([string]$Rule.DirectoryScopeId).Trim() }
        SeverityFloor = $severityFloor
        Reason = if ([string]::IsNullOrWhiteSpace([string]$Rule.Reason)) { $null } else { ([string]$Rule.Reason).Trim() }
        ApprovedBy = if ([string]::IsNullOrWhiteSpace([string]$Rule.ApprovedBy)) { $null } else { ([string]$Rule.ApprovedBy).Trim() }
        TicketId = if ([string]::IsNullOrWhiteSpace([string]$Rule.TicketId)) { $null } else { ([string]$Rule.TicketId).Trim() }
        ExpiresOn = if ($expiresOnValue) { $expiresOnValue.UtcDateTime.ToString('o') } else { $null }
        ExpiresOnDate = $expiresOnValue
        Specificity = 0
        Source = $SourceLabel
        Order = $Order
    }
}

function Get-RuleSpecificity {
    param([pscustomobject]$Rule)

    $specificFields = @(
        'FindingId',
        'UserPrincipalName',
        'DisplayName',
        'RoleDisplayName',
        'AssignmentState',
        'SourceGroupName',
        'AccessPath',
        'DirectoryScopeId'
    )

    $score = 0
    foreach ($field in $specificFields) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Rule.$field)) {
            $score++
        }
    }

    return $score
}

function Import-NormalizedRulesFromCsv {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Rules CSV not found: $Path"
    }

    $rows = @(Import-Csv -LiteralPath $Path)
    $rules = New-Object System.Collections.Generic.List[object]
    $order = 1
    foreach ($row in $rows) {
        $rule = New-NormalizedRule -Rule $row -Order $order -SourceLabel ("csv:{0}" -f $Path)
        $rule.Specificity = Get-RuleSpecificity -Rule $rule
        $rules.Add($rule)
        $order++
    }

    return $rules.ToArray()
}

function Import-NormalizedRulesFromJson {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Rules JSON not found: $Path"
    }

    $parsed = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 12
    $sourceRules = if ($parsed -is [System.Collections.IEnumerable] -and -not ($parsed -is [string])) {
        @($parsed)
    }
    elseif ($parsed.PSObject.Properties['rules']) {
        @($parsed.rules)
    }
    else {
        @($parsed)
    }

    $rules = New-Object System.Collections.Generic.List[object]
    $order = 1
    foreach ($sourceRule in $sourceRules) {
        $rule = New-NormalizedRule -Rule $sourceRule -Order $order -SourceLabel ("json:{0}" -f $Path)
        $rule.Specificity = Get-RuleSpecificity -Rule $rule
        $rules.Add($rule)
        $order++
    }

    return $rules.ToArray()
}

function Test-RuleMatchesFinding {
    param(
        [pscustomobject]$Rule,
        [pscustomobject]$Finding
    )

    if (-not $Rule.Enabled) {
        return $false
    }

    if ($Rule.FindingId -and ($Rule.FindingId -ne $Finding.FindingId)) {
        return $false
    }

    if ($Rule.UserPrincipalName -and (Get-NormalizedLookupKey -Value $Rule.UserPrincipalName) -ne (Get-NormalizedLookupKey -Value $Finding.UserPrincipalName)) {
        return $false
    }

    if ($Rule.DisplayName -and (Get-NormalizedLookupKey -Value $Rule.DisplayName) -ne (Get-NormalizedLookupKey -Value $Finding.DisplayName)) {
        return $false
    }

    if ($Rule.RoleDisplayName -and (Get-NormalizedLookupKey -Value $Rule.RoleDisplayName) -ne (Get-NormalizedLookupKey -Value $Finding.RoleDisplayName)) {
        return $false
    }

    if ($Rule.AssignmentState -and (Get-NormalizedLookupKey -Value $Rule.AssignmentState) -ne (Get-NormalizedLookupKey -Value $Finding.AssignmentState)) {
        return $false
    }

    if ($Rule.SourceGroupName -and (Get-NormalizedLookupKey -Value $Rule.SourceGroupName) -ne (Get-NormalizedLookupKey -Value $Finding.SourceGroupName)) {
        return $false
    }

    if ($Rule.AccessPath -and (Get-NormalizedLookupKey -Value $Rule.AccessPath) -ne (Get-NormalizedLookupKey -Value $Finding.AccessPath)) {
        return $false
    }

    if ($Rule.DirectoryScopeId -and ($Rule.DirectoryScopeId -ne [string]$Finding.DirectoryScopeId)) {
        return $false
    }

    if ($Rule.SeverityFloor -and ($SeverityRank[[string]$Finding.Severity] -lt $SeverityRank[$Rule.SeverityFloor])) {
        return $false
    }

    return $true
}

function Validate-NormalizedRules {
    param([object[]]$Rules)

    $validationErrors = New-Object System.Collections.Generic.List[string]
    $seenRuleIds = @{}

    foreach ($rule in @($Rules)) {
        if ($seenRuleIds.ContainsKey($rule.RuleId)) {
            $validationErrors.Add(("Duplicate RuleId detected: {0}" -f $rule.RuleId))
        }
        else {
            $seenRuleIds[$rule.RuleId] = $true
        }

        if ($rule.Mode -notin $AllowedRuleModes) {
            $validationErrors.Add(("Rule {0} has unsupported Mode '{1}'." -f $rule.RuleId, $rule.Mode))
        }

        if ($rule.Action -notin $AllowedRuleActions) {
            $validationErrors.Add(("Rule {0} has unsupported Action '{1}'." -f $rule.RuleId, $rule.Action))
        }

        if ($rule.Mode -eq 'Allow' -and $rule.Action -notin @('Keep', 'Ignore')) {
            $validationErrors.Add(("Rule {0} uses invalid Allow action '{1}'. Use Keep or Ignore." -f $rule.RuleId, $rule.Action))
        }

        if ($rule.Mode -eq 'Deny' -and $rule.Action -notin @('Remove', 'Disable')) {
            $validationErrors.Add(("Rule {0} uses invalid Deny action '{1}'. Use Remove or Disable." -f $rule.RuleId, $rule.Action))
        }

        if ($rule.Specificity -le 0) {
            $validationErrors.Add(("Rule {0} does not include any matching fields." -f $rule.RuleId))
        }

        if ($rule.SeverityFloor -and $rule.SeverityFloor -notin $SeverityRank.Keys) {
            $validationErrors.Add(("Rule {0} has unsupported SeverityFloor '{1}'." -f $rule.RuleId, $rule.SeverityFloor))
        }

        if ($rule.Mode -eq 'Allow') {
            if ([string]::IsNullOrWhiteSpace($rule.Reason)) {
                $validationErrors.Add(("Rule {0} is missing Reason." -f $rule.RuleId))
            }

            if ([string]::IsNullOrWhiteSpace($rule.ApprovedBy)) {
                $validationErrors.Add(("Rule {0} is missing ApprovedBy." -f $rule.RuleId))
            }
        }

        if ($rule.Mode -eq 'Deny' -and [string]::IsNullOrWhiteSpace($rule.Reason)) {
            $validationErrors.Add(("Rule {0} is missing Reason." -f $rule.RuleId))
        }
    }

    if ($validationErrors.Count -gt 0) {
        throw ($validationErrors -join [Environment]::NewLine)
    }
}

function Export-RulesToCsvContent {
    param([object[]]$Rules)

    $rows = foreach ($rule in @($Rules)) {
        [pscustomobject]@{
            RuleId = $rule.RuleId
            Enabled = [string]$rule.Enabled
            Mode = $rule.Mode
            Action = $rule.Action
            FindingId = $rule.FindingId
            UserPrincipalName = $rule.UserPrincipalName
            DisplayName = $rule.DisplayName
            RoleDisplayName = $rule.RoleDisplayName
            AssignmentState = $rule.AssignmentState
            SourceGroupName = $rule.SourceGroupName
            AccessPath = $rule.AccessPath
            DirectoryScopeId = $rule.DirectoryScopeId
            SeverityFloor = $rule.SeverityFloor
            Reason = $rule.Reason
            ApprovedBy = $rule.ApprovedBy
            TicketId = $rule.TicketId
            ExpiresOn = $rule.ExpiresOn
        }
    }

    return ($rows | Select-Object $RuleExportColumns | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine
}

function Get-ResolvedRulesNormalizedPath {
    if ($PSBoundParameters.ContainsKey('RulesNormalizedPath')) {
        return $RulesNormalizedPath
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Csv' {
            $directory = Split-Path -Path $RulesCsv -Parent
            if ([string]::IsNullOrWhiteSpace($directory)) {
                $directory = '.'
            }

            return (Join-Path $directory 'rules.normalized.json')
        }
        'Json' {
            $directory = Split-Path -Path $RulesJson -Parent
            if ([string]::IsNullOrWhiteSpace($directory)) {
                $directory = '.'
            }

            return (Join-Path $directory 'rules.normalized.json')
        }
        default {
            return '.\prontoso\rules.normalized.json'
        }
    }
}

function Write-NormalizedRulesJson {
    param(
        [string]$Path,
        [object[]]$Rules
    )

    $serializableRules = foreach ($rule in @($Rules)) {
        [pscustomobject]@{
            RuleId = $rule.RuleId
            Enabled = [bool]$rule.Enabled
            Mode = $rule.Mode
            Action = $rule.Action
            FindingId = $rule.FindingId
            UserPrincipalName = $rule.UserPrincipalName
            DisplayName = $rule.DisplayName
            RoleDisplayName = $rule.RoleDisplayName
            AssignmentState = $rule.AssignmentState
            SourceGroupName = $rule.SourceGroupName
            AccessPath = $rule.AccessPath
            DirectoryScopeId = $rule.DirectoryScopeId
            SeverityFloor = $rule.SeverityFloor
            Reason = $rule.Reason
            ApprovedBy = $rule.ApprovedBy
            TicketId = $rule.TicketId
            ExpiresOn = $rule.ExpiresOn
            Source = $rule.Source
            Order = $rule.Order
            Specificity = $rule.Specificity
        }
    }

    $json = if ($serializableRules.Count -gt 0) {
        $ruleJsonItems = foreach ($serializableRule in @($serializableRules)) {
            ConvertTo-Json -InputObject $serializableRule -Depth 12 -Compress
        }

        "[`n  {0}`n]" -f ($ruleJsonItems -join ",`n  ")
    }
    else {
        '[]'
    }

    Write-FileUtf8 -Path $Path -Content $json
}

function Get-ConsoleGuiAvailability {
    $hasModule = [bool](Get-Module -ListAvailable Microsoft.PowerShell.ConsoleGuiTools)
    $isInteractive = [Environment]::UserInteractive
    $inputRedirected = [Console]::IsInputRedirected
    $outputRedirected = [Console]::IsOutputRedirected

    [pscustomobject]@{
        HasModule = $hasModule
        CanUseGui = ($hasModule -and $isInteractive -and (-not $inputRedirected) -and (-not $outputRedirected))
    }
}

function Read-Choice {
    param(
        [string]$Title,
        [string]$Message,
        [string[]]$Labels,
        [int]$DefaultIndex = 0
    )

    $choices = New-Object 'System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]'
    foreach ($label in $Labels) {
        $choices.Add((New-Object System.Management.Automation.Host.ChoiceDescription "&$label", $label))
    }

    return $Host.UI.PromptForChoice($Title, $Message, $choices, $DefaultIndex)
}

function Expand-IndexSelection {
    param(
        [string]$InputText,
        [int]$UpperBound
    )

    $selected = New-Object System.Collections.Generic.HashSet[int]
    foreach ($token in (($InputText -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        if ($token -match '^(\d+)-(\d+)$') {
            $start = [int]$Matches[1]
            $end = [int]$Matches[2]
            if ($end -lt $start) {
                throw "Invalid range '$token'."
            }

            foreach ($index in $start..$end) {
                if ($index -lt 1 -or $index -gt $UpperBound) {
                    throw "Selection '$index' is outside the valid range 1-$UpperBound."
                }

                $null = $selected.Add($index)
            }

            continue
        }

        if ($token -notmatch '^\d+$') {
            throw "Invalid selection token '$token'."
        }

        $indexValue = [int]$token
        if ($indexValue -lt 1 -or $indexValue -gt $UpperBound) {
            throw "Selection '$indexValue' is outside the valid range 1-$UpperBound."
        }

        $null = $selected.Add($indexValue)
    }

    return @($selected.ToArray() | Sort-Object)
}

function Select-FindingsWithPrompt {
    param([object[]]$Findings)

    if ($Findings.Count -eq 0) {
        return @()
    }

    $indexedFindings = @()
    $counter = 1
    foreach ($finding in $Findings) {
        $groupLabel = if ([string]::IsNullOrWhiteSpace([string]$finding.SourceGroupName)) { '-' } else { [string]$finding.SourceGroupName }
        Write-Host ("[{0}] {1} | {2} | {3} | {4} | {5}" -f $counter, $finding.UserPrincipalName, $finding.RoleDisplayName, $finding.Severity, $finding.AccessPath, $groupLabel)
        $indexedFindings += [pscustomobject]@{
            Index = $counter
            Finding = $finding
        }
        $counter++
    }

    $inputText = Read-Host 'Enter comma-separated row numbers or ranges to create Keep rules for (blank for none)'
    if ([string]::IsNullOrWhiteSpace($inputText)) {
        return @()
    }

    $indexes = Expand-IndexSelection -InputText $inputText -UpperBound $Findings.Count
    return @($indexedFindings | Where-Object { $_.Index -in $indexes } | ForEach-Object { $_.Finding })
}

function Select-FindingsWithConsoleGui {
    param([object[]]$Findings)

    Import-Module Microsoft.PowerShell.ConsoleGuiTools -ErrorAction Stop | Out-Null

    $gridRows = foreach ($finding in $Findings) {
        [pscustomobject]@{
            FindingId = $finding.FindingId
            UserPrincipalName = $finding.UserPrincipalName
            DisplayName = $finding.DisplayName
            RoleDisplayName = $finding.RoleDisplayName
            Severity = $finding.Severity
            AccessPath = $finding.AccessPath
            SourceGroupName = $finding.SourceGroupName
            ReviewState = $finding.ReviewState
        }
    }

    $selectedRows = @($gridRows | Out-ConsoleGridView -Title 'Select findings to keep as sanctioned exceptions' -PassThru)
    if ($selectedRows.Count -eq 0) {
        return @()
    }

    $selectedIds = @($selectedRows | ForEach-Object { $_.FindingId })
    return @($Findings | Where-Object { $_.FindingId -in $selectedIds })
}

function Read-InteractiveRuleDetails {
    param([pscustomobject]$Finding)

    Write-Host ''
    Write-Host ("Creating Keep rule for {0} | {1}" -f $Finding.UserPrincipalName, $Finding.RoleDisplayName) -ForegroundColor Yellow

    $reason = $null
    while ([string]::IsNullOrWhiteSpace($reason)) {
        $reason = Read-Host 'Reason'
    }

    $approvedByDefault = if ($script:CurrentActorUpn) { $script:CurrentActorUpn } else { '' }
    $approvedBy = Read-Host ("ApprovedBy [{0}]" -f $approvedByDefault)
    if ([string]::IsNullOrWhiteSpace($approvedBy)) {
        $approvedBy = $approvedByDefault
    }

    while ([string]::IsNullOrWhiteSpace($approvedBy)) {
        $approvedBy = Read-Host 'ApprovedBy'
    }

    $ticketId = Read-Host 'TicketId (optional)'
    $expiresOnInput = Read-Host 'ExpiresOn UTC ISO-8601 (optional, blank for none)'
    $expiresOn = if ([string]::IsNullOrWhiteSpace($expiresOnInput)) {
        $null
    }
    else {
        (Get-DateOrNull -Value $expiresOnInput).UtcDateTime.ToString('o')
    }

    [pscustomobject]@{
        Reason = $reason
        ApprovedBy = $approvedBy
        TicketId = if ([string]::IsNullOrWhiteSpace($ticketId)) { $null } else { $ticketId.Trim() }
        ExpiresOn = $expiresOn
    }
}

function Show-RulePreview {
    param([object[]]$Rules)

    if ($Rules.Count -eq 0) {
        Write-Info 'No active rules loaded.'
        return
    }

    $preview = $Rules |
        Sort-Object @{ Expression = 'Mode'; Descending = $true }, @{ Expression = 'Specificity'; Descending = $true }, Order |
        Select-Object RuleId, Enabled, Mode, Action, UserPrincipalName, RoleDisplayName, AssignmentState, SourceGroupName, ExpiresOn, TicketId

    $table = $preview | Format-Table -AutoSize | Out-String
    Write-Host $table
}

function Import-ActiveRules {
    $normalizedPath = Get-ResolvedRulesNormalizedPath

    switch ($PSCmdlet.ParameterSetName) {
        'Csv' {
            $rules = @(Import-NormalizedRulesFromCsv -Path $RulesCsv)
        }
        'Json' {
            $rules = @(Import-NormalizedRulesFromJson -Path $RulesJson)
        }
        default {
            Initialize-RulesCsvTemplate -Path $InteractiveRulesCsvPath
            $rules = @(Import-NormalizedRulesFromCsv -Path $InteractiveRulesCsvPath)
        }
    }

    Validate-NormalizedRules -Rules $rules
    return [pscustomobject]@{
        Rules = $rules
        NormalizedPath = $normalizedPath
    }
}

function Invoke-InteractiveRuleAuthoring {
    param(
        [object[]]$Findings,
        [object[]]$ExistingRules
    )

    $rules = New-Object System.Collections.Generic.List[object]
    foreach ($existingRule in @($ExistingRules)) {
        $rules.Add($existingRule)
    }

    $activeAllowKeepKeys = @{}
    foreach ($rule in @($ExistingRules | Where-Object { $_.Enabled -and $_.Mode -eq 'Allow' -and $_.Action -in @('Keep', 'Ignore') })) {
        if ($rule.FindingId) {
            $activeAllowKeepKeys[$rule.FindingId] = $true
        }
    }

    $selectableFindings = @($Findings | Where-Object { -not $activeAllowKeepKeys.ContainsKey($_.FindingId) })
    if ($selectableFindings.Count -eq 0) {
        Write-Info 'No findings remain for interactive Keep-rule authoring.'
        return $rules.ToArray()
    }

    $choiceIndex = Read-Choice -Title 'Rules' -Message 'Add or update sanctioned Keep rules before remediation?' -Labels @('Yes', 'No') -DefaultIndex 1
    if ($choiceIndex -ne 0) {
        return $rules.ToArray()
    }

    $guiAvailability = Get-ConsoleGuiAvailability
    $useGuiSelection = $false
    if ($UseConsoleGui) {
        if ($guiAvailability.CanUseGui) {
            $useGuiSelection = $true
        }
        else {
            Write-WarnLine 'UseConsoleGui requested, but the current session cannot host ConsoleGuiTools. Falling back to prompt mode.'
        }
    }

    $selectedFindings = if ($useGuiSelection) {
        Select-FindingsWithConsoleGui -Findings $selectableFindings
    }
    else {
        Select-FindingsWithPrompt -Findings $selectableFindings
    }

    foreach ($selectedFinding in @($selectedFindings)) {
        $details = Read-InteractiveRuleDetails -Finding $selectedFinding
        $ruleId = Get-NextRuleId -ExistingRules $rules.ToArray()

        $newRule = New-NormalizedRule -Rule ([pscustomobject]@{
                RuleId = $ruleId
                Enabled = $true
                Mode = 'Allow'
                Action = 'Keep'
                FindingId = $selectedFinding.FindingId
                UserPrincipalName = $selectedFinding.UserPrincipalName
                DisplayName = $selectedFinding.DisplayName
                RoleDisplayName = $selectedFinding.RoleDisplayName
                AssignmentState = $selectedFinding.AssignmentState
                SourceGroupName = $selectedFinding.SourceGroupName
                AccessPath = $selectedFinding.AccessPath
                DirectoryScopeId = $selectedFinding.DirectoryScopeId
                SeverityFloor = $selectedFinding.Severity
                Reason = $details.Reason
                ApprovedBy = $details.ApprovedBy
                TicketId = $details.TicketId
                ExpiresOn = $details.ExpiresOn
            }) -Order ($rules.Count + 1) -SourceLabel 'interactive'
        $newRule.Specificity = Get-RuleSpecificity -Rule $newRule
        $rules.Add($newRule)
    }

    Validate-NormalizedRules -Rules $rules.ToArray()
    return $rules.ToArray()
}

function Resolve-FindingDecision {
    param(
        [pscustomobject]$Finding,
        [object[]]$Rules,
        [int]$MinimumSeverityRank
    )

    $expiredRuleMatches = New-Object System.Collections.Generic.List[object]
    $matchingRules = New-Object System.Collections.Generic.List[object]

    foreach ($rule in @($Rules)) {
        if (-not (Test-RuleMatchesFinding -Rule $rule -Finding $Finding)) {
            continue
        }

        $isExpired = ($null -ne $rule.ExpiresOnDate -and $rule.ExpiresOnDate -lt [DateTimeOffset]::UtcNow)
        if ($isExpired) {
            $expiredRuleMatches.Add($rule)
            continue
        }

        $matchingRules.Add($rule)
    }

    $matchedRule = @(
        $matchingRules |
            Sort-Object `
                @{ Expression = { if ($_.Mode -eq 'Deny') { 2 } else { 1 } }; Descending = $true }, `
                @{ Expression = 'Specificity'; Descending = $true }, `
                @{ Expression = 'Order'; Descending = $false }
    ) | Select-Object -First 1

    $severityRank = $SeverityRank[[string]$Finding.Severity]
    $include = $severityRank -ge $MinimumSeverityRank
    $decision = 'ExcludedBySeverityThreshold'
    $disableUser = $false

    if ($include) {
        $decision = 'RemediateBySeverity'
    }

    if ($matchedRule) {
        switch ("{0}:{1}" -f $matchedRule.Mode, $matchedRule.Action) {
            'Allow:Keep' { $include = $false; $decision = 'ExcludedByAllowRule' }
            'Allow:Ignore' { $include = $false; $decision = 'ExcludedByAllowRule' }
            'Deny:Remove' { $include = $true; $decision = 'RemediateByDenyRule' }
            'Deny:Disable' { $include = $true; $disableUser = $true; $decision = 'RemediateAndDisableByDenyRule' }
            default { throw "Unsupported rule decision path '$($matchedRule.Mode):$($matchedRule.Action)'." }
        }
    }

    return [pscustomobject]@{
        IncludeInRemediation = $include
        DisableUser = $disableUser
        Decision = $decision
        MatchedRule = $matchedRule
        ExpiredRuleIds = @($expiredRuleMatches | ForEach-Object { $_.RuleId })
        ExpiredRuleCount = $expiredRuleMatches.Count
    }
}

function Add-ManifestOperation {
    param(
        [System.Collections.Generic.List[object]]$Operations,
        [int]$Sequence,
        [pscustomobject]$Finding,
        [pscustomobject]$Decision,
        [hashtable]$Fields
    )

    $operation = [ordered]@{
        Sequence = $Sequence
        FindingId = $Finding.FindingId
        UserId = $Finding.UserId
        UserPrincipalName = $Finding.UserPrincipalName
        PrincipalDisplayName = $Finding.DisplayName
        RoleDisplayName = $Finding.RoleDisplayName
        DirectoryScopeId = $Finding.DirectoryScopeId
        FindingSeverity = $Finding.Severity
        AuthorizingRuleId = if ($Decision.MatchedRule) { $Decision.MatchedRule.RuleId } else { $null }
        AuthorizingRuleMode = if ($Decision.MatchedRule) { $Decision.MatchedRule.Mode } else { $null }
        AuthorizingRuleAction = if ($Decision.MatchedRule) { $Decision.MatchedRule.Action } else { $null }
        AuthorizingRuleReason = if ($Decision.MatchedRule) { $Decision.MatchedRule.Reason } else { $null }
        AuthorizingRuleTicketId = if ($Decision.MatchedRule) { $Decision.MatchedRule.TicketId } else { $null }
    }

    foreach ($key in $Fields.Keys) {
        $operation[$key] = $Fields[$key]
    }

    $Operations.Add([pscustomobject]$operation)
}

function Invoke-OnlineValidation {
    param(
        [object[]]$Findings,
        [object[]]$Rules,
        [object]$RollbackManifest
    )

    Initialize-GraphConnection -Scopes $ValidationScopes -SkipWhenValidateOnly

    $validationIssues = New-Object System.Collections.Generic.List[string]
    $seenUsers = @{}
    $seenGroups = @{}

    foreach ($finding in @($Findings)) {
        if (-not $seenUsers.ContainsKey($finding.UserId)) {
            $seenUsers[$finding.UserId] = $true
            if (-not (Test-GraphObjectExists -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select=id" -f $finding.UserId))) {
                $validationIssues.Add(("Finding {0} references missing user {1} ({2})." -f $finding.FindingId, $finding.UserPrincipalName, $finding.UserId))
            }
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$finding.SourceGroupId) -and -not $seenGroups.ContainsKey($finding.SourceGroupId)) {
            $seenGroups[$finding.SourceGroupId] = $true
            if (-not (Test-GraphObjectExists -Uri ("https://graph.microsoft.com/v1.0/groups/{0}?`$select=id" -f $finding.SourceGroupId))) {
                $validationIssues.Add(("Finding {0} references missing group {1} ({2})." -f $finding.FindingId, $finding.SourceGroupName, $finding.SourceGroupId))
            }
        }
    }

    foreach ($rule in @($Rules)) {
        if ($rule.FindingId -and -not (@($Findings | Where-Object { $_.FindingId -eq $rule.FindingId }).Count -gt 0)) {
            $validationIssues.Add(("Rule {0} references FindingId {1}, which is not present in the findings file." -f $rule.RuleId, $rule.FindingId))
        }
    }

    if ($null -ne $RollbackManifest) {
        foreach ($operation in @($RollbackManifest.operations)) {
            if ($operation.UserId -and -not $seenUsers.ContainsKey($operation.UserId)) {
                $seenUsers[$operation.UserId] = $true
                if (-not (Test-GraphObjectExists -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select=id" -f $operation.UserId))) {
                    $validationIssues.Add(("Rollback operation {0} references missing user {1}." -f $operation.Sequence, $operation.UserId))
                }
            }

            if ($operation.GroupId -and -not $seenGroups.ContainsKey($operation.GroupId)) {
                $seenGroups[$operation.GroupId] = $true
                if (-not (Test-GraphObjectExists -Uri ("https://graph.microsoft.com/v1.0/groups/{0}?`$select=id" -f $operation.GroupId))) {
                    $validationIssues.Add(("Rollback operation {0} references missing group {1}." -f $operation.Sequence, $operation.GroupId))
                }
            }
        }
    }

    if ($validationIssues.Count -gt 0) {
        throw ($validationIssues -join [Environment]::NewLine)
    }

    Write-Info 'Online validation completed. Referenced users and groups exist.'
}

function Get-GraphContextStatus {
    param([string[]]$Scopes = $RequiredScopes)

    $context = Get-MgContext
    if ($null -eq $context) {
        return [pscustomobject]@{
            Connected = $false
            MissingScopes = $Scopes
            Context = $null
        }
    }

    $existingScopes = @($context.Scopes)
    $missingScopes = @($Scopes | Where-Object { $_ -notin $existingScopes })

    [pscustomobject]@{
        Connected = $true
        MissingScopes = $missingScopes
        Context = $context
    }
}

function Initialize-GraphConnection {
    param(
        [string[]]$Scopes = $RequiredScopes,
        [switch]$SkipWhenValidateOnly
    )

    if ($ValidateOnly -and -not $SkipWhenValidateOnly) {
        Write-Info 'ValidateOnly set. Skipping Graph authentication.'
        return
    }

    $status = Get-GraphContextStatus -Scopes $Scopes
    $mustReconnect = -not $status.Connected -or $status.MissingScopes.Count -gt 0

    if ($status.Connected -and $status.Context.TenantId -and $TenantIdOrDomain -and ($status.Context.TenantId -ne $TenantIdOrDomain) -and ($status.Context.Account -notlike "*@$TenantIdOrDomain")) {
        $mustReconnect = $true
    }

    if ($mustReconnect) {
        Write-Info ("Connecting to Microsoft Graph for tenant '{0}' with scopes: {1}" -f $TenantIdOrDomain, ($Scopes -join ', '))
        if ($UseDeviceAuthentication) {
            Connect-MgGraph -TenantId $TenantIdOrDomain -Scopes $Scopes -UseDeviceAuthentication -NoWelcome | Out-Null
        }
        else {
            Connect-MgGraph -TenantId $TenantIdOrDomain -Scopes $Scopes -NoWelcome | Out-Null
        }
    }
    else {
        Write-Info ("Reusing Graph context for {0}" -f $status.Context.Account)
    }

    $context = Get-MgContext
    $script:CurrentActorUpn = if ($context) { [string]$context.Account } else { $null }
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

        $nextLinkProperty = $response.PSObject.Properties['@odata.nextLink']
        $nextUri = if ($nextLinkProperty) { [string]$nextLinkProperty.Value } else { $null }
    }

    return $results.ToArray()
}

function Test-GraphNotFound {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $message = (($ErrorRecord | Out-String) + [string]$ErrorRecord.Exception.Message)
    return $message -match '404' -or $message -match 'Request_ResourceNotFound' -or $message -match 'NotFound'
}

function Test-GraphObjectExists {
    param([string]$Uri)

    try {
        $null = Invoke-GraphJson -Uri $Uri
        return $true
    }
    catch {
        if (Test-GraphNotFound -ErrorRecord $_) {
            return $false
        }

        throw
    }
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

function Remove-LegacyDirectoryRoleMember {
    param(
        [string]$DirectoryRoleId,
        [string]$UserId,
        [string]$UserPrincipalName
    )

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Remove legacy directory role membership')) {
        Invoke-GraphJson -Uri ("https://graph.microsoft.com/v1.0/directoryRoles/{0}/members/{1}/`$ref" -f $DirectoryRoleId, $UserId) -Method 'DELETE' | Out-Null
        return 'Removed'
    }

    return 'WhatIf'
}

function Restore-LegacyDirectoryRoleMember {
    param(
        [string]$DirectoryRoleId,
        [string]$UserId,
        [string]$UserPrincipalName
    )

    $body = @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$UserId"
    }

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Restore legacy directory role membership')) {
        Invoke-GraphJson -Uri ("https://graph.microsoft.com/v1.0/directoryRoles/{0}/members/`$ref" -f $DirectoryRoleId) -Method 'POST' -Body $body | Out-Null
        return 'Restored'
    }

    return 'WhatIf'
}

function Test-ConflictingObjectError {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $message = (($ErrorRecord | Out-String) + [string]$ErrorRecord.Exception.Message)
    return $message -match 'conflicting object' -or $message -match 'added object references already exist'
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

Initialize-Directory -Path $OutputPath

if ($ValidateOnly) {
    if ($RollbackManifestPath) {
        if (-not (Test-Path -LiteralPath $RollbackManifestPath)) {
            throw "Rollback manifest not found: $RollbackManifestPath"
        }

        $rollbackManifest = Get-Content -LiteralPath $RollbackManifestPath -Raw | ConvertFrom-Json -Depth 12
        $findingsForValidation = @()
        $rulesForValidation = @()
        if ($ValidateOnline) {
            Invoke-OnlineValidation -Findings $findingsForValidation -Rules $rulesForValidation -RollbackManifest $rollbackManifest
        }
        Write-Info 'Rollback manifest validation complete.'
        return
    }
    else {
        if (-not (Test-Path -LiteralPath $FindingsPath)) {
            throw "Findings file not found: $FindingsPath"
        }

        $validatedFindings = @(Get-Content -LiteralPath $FindingsPath -Raw | ConvertFrom-Json -Depth 12)
        $validatedFindings = @(Initialize-FindingShape -Findings $validatedFindings)
        $ruleState = Import-ActiveRules
        Write-NormalizedRulesJson -Path $ruleState.NormalizedPath -Rules $ruleState.Rules

        if ($ValidateOnline) {
            Invoke-OnlineValidation -Findings $validatedFindings -Rules $ruleState.Rules -RollbackManifest $null
        }

        Write-Info ("Validated findings: {0}" -f $validatedFindings.Count)
        Write-Info ("Validated rules: {0}" -f $ruleState.Rules.Count)
        Write-Info ("Normalized rules written to {0}" -f $ruleState.NormalizedPath)
        return
    }
}

Initialize-GraphConnection

if ($RollbackManifestPath) {
    $manifest = Get-Content -LiteralPath $RollbackManifestPath -Raw | ConvertFrom-Json -Depth 12
    $rollbackResults = New-Object System.Collections.Generic.List[object]

    foreach ($operation in @($manifest.operations | Sort-Object Sequence -Descending)) {
        switch ($operation.OperationType) {
            'DeleteRoleAssignment' {
                if ($operation.LegacyRoleId) {
                    $status = Restore-LegacyDirectoryRoleMember -DirectoryRoleId $operation.LegacyRoleId -UserId $operation.PrincipalId -UserPrincipalName $operation.UserPrincipalName
                    $rollbackResults.Add([pscustomobject]@{
                            Sequence = $operation.Sequence
                            OperationType = $operation.OperationType
                            Status = $status
                            RestoredObjectId = $operation.LegacyRoleId
                            Target = $operation.PrincipalDisplayName
                            FindingId = $operation.FindingId
                            AuthorizingRuleId = $operation.AuthorizingRuleId
                        })
                }
                else {
                    $body = @{
                        principalId = $operation.PrincipalId
                        roleDefinitionId = $operation.RoleDefinitionId
                        directoryScopeId = $operation.DirectoryScopeId
                    }

                    if ($PSCmdlet.ShouldProcess($operation.PrincipalDisplayName, 'Recreate role assignment')) {
                        try {
                            $created = Invoke-GraphJson -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' -Method 'POST' -Body $body
                            $status = 'Restored'
                            $restoredObjectId = $created.id
                        }
                        catch {
                            if (-not (Test-ConflictingObjectError -ErrorRecord $_)) {
                                throw
                            }

                            $status = 'AlreadyRestored'
                            $restoredObjectId = $null
                        }

                        $rollbackResults.Add([pscustomobject]@{
                                Sequence = $operation.Sequence
                                OperationType = $operation.OperationType
                                Status = $status
                                RestoredObjectId = $restoredObjectId
                                Target = $operation.PrincipalDisplayName
                                FindingId = $operation.FindingId
                                AuthorizingRuleId = $operation.AuthorizingRuleId
                            })
                    }
                }
            }
            'RemoveGroupMember' {
                $body = @{
                    '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($operation.UserId)"
                }

                if ($PSCmdlet.ShouldProcess($operation.UserPrincipalName, 'Re-add group membership')) {
                    try {
                        Invoke-GraphJson -Uri ("https://graph.microsoft.com/v1.0/groups/{0}/members/`$ref" -f $operation.GroupId) -Method 'POST' -Body $body | Out-Null
                        $status = 'Restored'
                    }
                    catch {
                        if (-not (Test-ConflictingObjectError -ErrorRecord $_)) {
                            throw
                        }

                        $status = 'AlreadyRestored'
                    }

                    $rollbackResults.Add([pscustomobject]@{
                            Sequence = $operation.Sequence
                            OperationType = $operation.OperationType
                            Status = $status
                            RestoredObjectId = $operation.GroupId
                            Target = $operation.UserPrincipalName
                            FindingId = $operation.FindingId
                            AuthorizingRuleId = $operation.AuthorizingRuleId
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
                        FindingId = $operation.FindingId
                        AuthorizingRuleId = $operation.AuthorizingRuleId
                    })
            }
            'SkippedSelfProtection' {
                $rollbackResults.Add([pscustomobject]@{
                        Sequence = $operation.Sequence
                        OperationType = $operation.OperationType
                        Status = 'Ignored'
                        RestoredObjectId = $null
                        Target = $operation.UserPrincipalName
                        FindingId = $operation.FindingId
                        AuthorizingRuleId = $operation.AuthorizingRuleId
                    })
            }
            default {
                throw "Unsupported rollback operation type '$($operation.OperationType)'."
            }
        }
    }

    $rollbackResultPath = Join-Path $OutputPath 'rollback-results.json'
    Write-FileUtf8 -Path $rollbackResultPath -Content ($rollbackResults | ConvertTo-Json -Depth 12)
    Write-Info ("Rollback results written to {0}" -f $rollbackResultPath)
    return
}

if (-not (Test-Path -LiteralPath $FindingsPath)) {
    throw "Findings file not found: $FindingsPath"
}

$findings = @(Get-Content -LiteralPath $FindingsPath -Raw | ConvertFrom-Json -Depth 12)
$findings = @(Initialize-FindingShape -Findings $findings)
$minimumRank = $SeverityRank[$MinimumSeverity]

$ruleState = Import-ActiveRules
$rules = @($ruleState.Rules)
$normalizedRulesPath = $ruleState.NormalizedPath

if ($PSCmdlet.ParameterSetName -eq 'Interactive') {
    $rules = @(Invoke-InteractiveRuleAuthoring -Findings $findings -ExistingRules $rules)

    if (-not [string]::IsNullOrWhiteSpace($InteractiveRulesCsvPath)) {
        $rulesCsvContent = Export-RulesToCsvContent -Rules $rules
        Write-FileUtf8 -Path $InteractiveRulesCsvPath -Content $rulesCsvContent
        Write-Info ("Interactive rules written to {0}" -f $InteractiveRulesCsvPath)
    }
}

Validate-NormalizedRules -Rules $rules
Write-NormalizedRulesJson -Path $normalizedRulesPath -Rules $rules
Write-Info ("Normalized rules written to {0}" -f $normalizedRulesPath)
Show-RulePreview -Rules $rules

$evaluationRecords = New-Object System.Collections.Generic.List[object]
$candidateFindings = New-Object System.Collections.Generic.List[object]

foreach ($finding in @($findings)) {
    $decision = Resolve-FindingDecision -Finding $finding -Rules $rules -MinimumSeverityRank $minimumRank
    $evaluationRecords.Add([pscustomobject]@{
            FindingId = $finding.FindingId
            UserPrincipalName = $finding.UserPrincipalName
            DisplayName = $finding.DisplayName
            RoleDisplayName = $finding.RoleDisplayName
            Severity = $finding.Severity
            ReviewState = $finding.ReviewState
            Decision = $decision.Decision
            IncludeInRemediation = [bool]$decision.IncludeInRemediation
            DisableUser = [bool]$decision.DisableUser
            MatchedRuleId = if ($decision.MatchedRule) { $decision.MatchedRule.RuleId } else { $null }
            MatchedRuleMode = if ($decision.MatchedRule) { $decision.MatchedRule.Mode } else { $null }
            MatchedRuleAction = if ($decision.MatchedRule) { $decision.MatchedRule.Action } else { $null }
            ExpiredRuleIds = @($decision.ExpiredRuleIds)
            ExpiredRuleCount = $decision.ExpiredRuleCount
        })

    if ($decision.IncludeInRemediation) {
        $finding | Add-Member -NotePropertyName ResolvedDecision -NotePropertyValue $decision -Force
        $candidateFindings.Add($finding)
    }
}

if ($PSCmdlet.ParameterSetName -eq 'Interactive') {
    $continueChoice = Read-Choice -Title 'Remediation' -Message ("Continue with {0} candidate findings?" -f $candidateFindings.Count) -Labels @('Continue', 'Cancel') -DefaultIndex 1
    if ($continueChoice -ne 0) {
        Write-WarnLine 'Interactive remediation cancelled after rules were saved.'
        return
    }
}

$manifest = [ordered]@{
    generatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    tenant = $TenantIdOrDomain
    minimumSeverity = $MinimumSeverity
    disableAccounts = [bool]$DisableAccounts
    findingsCount = $candidateFindings.Count
    totalFindingsEvaluated = $findings.Count
    rulesCount = $rules.Count
    rulesNormalizedPath = $normalizedRulesPath
    operations = (New-Object System.Collections.Generic.List[object])
}

$seenRoleAssignments = @{}
$seenGroupMemberships = @{}
$seenDisabledUsers = @{}
$sequence = 1

foreach ($finding in $candidateFindings) {
    $decision = $finding.ResolvedDecision

    if ($CurrentActorUpn -and $finding.UserPrincipalName -eq $CurrentActorUpn) {
        Add-ManifestOperation -Operations $manifest.operations -Sequence $sequence -Finding $finding -Decision $decision -Fields @{
            OperationType = 'SkippedSelfProtection'
            Status = 'Skipped'
        }
        $sequence++
        continue
    }

    if ($finding.AccessPath -eq 'Direct') {
        $roleKey = '{0}|{1}|{2}' -f $finding.UserId, $finding.RoleDefinitionId, $finding.DirectoryScopeId
        if (-not $seenRoleAssignments.ContainsKey($roleKey)) {
            $seenRoleAssignments[$roleKey] = $true
            if ($finding.LegacyRoleId) {
                $status = Remove-LegacyDirectoryRoleMember -DirectoryRoleId $finding.LegacyRoleId -UserId $finding.UserId -UserPrincipalName $finding.UserPrincipalName
                Add-ManifestOperation -Operations $manifest.operations -Sequence $sequence -Finding $finding -Decision $decision -Fields @{
                    OperationType = 'DeleteRoleAssignment'
                    Status = $status
                    RoleAssignmentId = $finding.AssignmentInstanceId
                    LegacyRoleId = $finding.LegacyRoleId
                    PrincipalId = $finding.UserId
                    RoleDefinitionId = $finding.RoleDefinitionId
                }
                $sequence++
            }
            else {
                $currentAssignments = Get-CurrentRoleAssignments -PrincipalId $finding.UserId -RoleDefinitionId $finding.RoleDefinitionId -DirectoryScopeId $finding.DirectoryScopeId
                foreach ($assignment in $currentAssignments) {
                    if ($PSCmdlet.ShouldProcess($finding.UserPrincipalName, ("Delete direct role assignment {0}" -f $finding.RoleDisplayName))) {
                        Invoke-GraphJson -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/{0}" -f $assignment.id) -Method 'DELETE' | Out-Null
                        $status = 'Deleted'
                    }
                    else {
                        $status = 'WhatIf'
                    }

                    Add-ManifestOperation -Operations $manifest.operations -Sequence $sequence -Finding $finding -Decision $decision -Fields @{
                        OperationType = 'DeleteRoleAssignment'
                        Status = $status
                        RoleAssignmentId = $assignment.id
                        LegacyRoleId = $null
                        PrincipalId = $finding.UserId
                        RoleDefinitionId = $finding.RoleDefinitionId
                    }
                    $sequence++
                }
            }
        }
    }
    elseif ($finding.AccessPath -eq 'Group' -and $finding.SourceGroupId) {
        $groupKey = '{0}|{1}' -f $finding.SourceGroupId, $finding.UserId
        if (-not $seenGroupMemberships.ContainsKey($groupKey)) {
            $seenGroupMemberships[$groupKey] = $true
            $directMembership = Get-DirectGroupMembership -GroupId $finding.SourceGroupId -UserId $finding.UserId
            if ($directMembership.Count -eq 0) {
                Add-ManifestOperation -Operations $manifest.operations -Sequence $sequence -Finding $finding -Decision $decision -Fields @{
                    OperationType = 'RemoveGroupMember'
                    Status = 'SkippedNestedOrMissing'
                    GroupId = $finding.SourceGroupId
                    GroupDisplayName = $finding.SourceGroupName
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

                Add-ManifestOperation -Operations $manifest.operations -Sequence $sequence -Finding $finding -Decision $decision -Fields @{
                    OperationType = 'RemoveGroupMember'
                    Status = $status
                    GroupId = $finding.SourceGroupId
                    GroupDisplayName = $finding.SourceGroupName
                }
                $sequence++
            }
        }
    }

    $shouldDisableThisUser = $DisableAccounts -or $decision.DisableUser
    if ($shouldDisableThisUser -and -not $seenDisabledUsers.ContainsKey($finding.UserId)) {
        $seenDisabledUsers[$finding.UserId] = $true
        $disableResult = Disable-UserAccount -UserId $finding.UserId -UserPrincipalName $finding.UserPrincipalName
        Add-ManifestOperation -Operations $manifest.operations -Sequence $sequence -Finding $finding -Decision $decision -Fields @{
            OperationType = 'DisableUser'
            Status = $disableResult.Action
            PreviousAccountEnabled = [bool]$disableResult.PreviousAccountEnabled
        }
        $sequence++
    }
}

$manifestPath = Join-Path $OutputPath 'remediation-manifest.json'
$summaryPath = Join-Path $OutputPath 'remediation-summary.md'
$manualReviewJsonPath = Join-Path $OutputPath 'needs-manual-review.json'
$manualReviewCsvPath = Join-Path $OutputPath 'needs-manual-review.csv'
$ruleEvaluationJsonPath = Join-Path $OutputPath 'rule-evaluation.json'
$ruleEvaluationCsvPath = Join-Path $OutputPath 'rule-evaluation.csv'

$manifestJson = $manifest | ConvertTo-Json -Depth 12
$statusCounts = @($manifest.operations | Group-Object Status | Sort-Object Name)
$decisionCounts = @($evaluationRecords | Group-Object Decision | Sort-Object Name)
$manualReviewOperations = @($manifest.operations | Where-Object { $_.Status -eq 'SkippedNestedOrMissing' })
$expiredRuleEvaluations = @($evaluationRecords | Where-Object { $_.ExpiredRuleCount -gt 0 })
$allowRuleExclusions = @($evaluationRecords | Where-Object { $_.Decision -eq 'ExcludedByAllowRule' })
$denyRuleCandidates = @($evaluationRecords | Where-Object { $_.Decision -like 'Remediate*DenyRule*' })

$summaryLines = New-Object System.Collections.Generic.List[string]
foreach ($line in @(
        '# Entra Privileged Remediation'
        ''
        ('Tenant: `{0}`' -f $TenantIdOrDomain)
        ('Minimum severity: `{0}`' -f $MinimumSeverity)
        ('Disable accounts (global): `{0}`' -f [bool]$DisableAccounts)
        ('Findings evaluated: `{0}`' -f $findings.Count)
        ('Candidate findings: `{0}`' -f $candidateFindings.Count)
        ('Recorded operations: `{0}`' -f $manifest.operations.Count)
        ('Rules loaded: `{0}`' -f $rules.Count)
        ('Normalized rules: `{0}`' -f $normalizedRulesPath)
        ('Rule evaluation artifacts: `{0}`, `{1}`' -f $ruleEvaluationJsonPath, $ruleEvaluationCsvPath)
    )) {
    $summaryLines.Add([string]$line)
}

if ($decisionCounts.Count -gt 0) {
    $summaryLines.Add('')
    $summaryLines.Add('## Rule Decisions')
    foreach ($decisionCount in $decisionCounts) {
        $summaryLines.Add(('- `{0}`: {1}' -f $decisionCount.Name, $decisionCount.Count))
    }
}

if ($statusCounts.Count -gt 0) {
    $summaryLines.Add('')
    $summaryLines.Add('## Operation Status Counts')
    foreach ($statusCount in $statusCounts) {
        $summaryLines.Add(('- `{0}`: {1}' -f $statusCount.Name, $statusCount.Count))
    }
}

if ($allowRuleExclusions.Count -gt 0) {
    $summaryLines.Add('')
    $summaryLines.Add(('## Kept by Allow Rules ({0})' -f $allowRuleExclusions.Count))
    foreach ($entry in $allowRuleExclusions | Select-Object -First 15) {
        $summaryLines.Add(('- `{0}` | `{1}` | Rule `{2}`' -f $entry.UserPrincipalName, $entry.RoleDisplayName, $entry.MatchedRuleId))
    }
}

if ($denyRuleCandidates.Count -gt 0) {
    $summaryLines.Add('')
    $summaryLines.Add(('## Forced by Deny Rules ({0})' -f $denyRuleCandidates.Count))
    foreach ($entry in $denyRuleCandidates | Select-Object -First 15) {
        $summaryLines.Add(('- `{0}` | `{1}` | Rule `{2}`' -f $entry.UserPrincipalName, $entry.RoleDisplayName, $entry.MatchedRuleId))
    }
}

if ($expiredRuleEvaluations.Count -gt 0) {
    $summaryLines.Add('')
    $summaryLines.Add(('## Expired Rule Matches ({0})' -f $expiredRuleEvaluations.Count))
    $summaryLines.Add('These findings matched one or more expired rules and were evaluated without those expired rules in force.')
    foreach ($entry in $expiredRuleEvaluations | Select-Object -First 15) {
        $summaryLines.Add(('- `{0}` | `{1}` | Expired rules: `{2}`' -f $entry.UserPrincipalName, $entry.RoleDisplayName, ($entry.ExpiredRuleIds -join ', ')))
    }
}

if ($manualReviewOperations.Count -gt 0) {
    $summaryLines.Add('')
    $summaryLines.Add(('## Skipped - Nested or Missing Group Memberships ({0})' -f $manualReviewOperations.Count))
    $summaryLines.Add('These require manual review because the user is not a direct member of the privileged source group.')
    $summaryLines.Add(('Artifacts: `{0}`, `{1}`' -f $manualReviewJsonPath, $manualReviewCsvPath))

    foreach ($operation in $manualReviewOperations) {
        $summaryLines.Add(('- `{0}` via `{1}` (`{2}`)' -f $operation.UserPrincipalName, $operation.GroupDisplayName, $operation.RoleDisplayName))
    }
}

$summary = $summaryLines -join [Environment]::NewLine
$manualReviewJson = if ($manualReviewOperations.Count -gt 0) {
    $manualReviewOperations | ConvertTo-Json -Depth 12
}
else {
    '[]'
}
$manualReviewCsvRows = @(
    $manualReviewOperations |
        Select-Object Sequence, Status, FindingId, AuthorizingRuleId, UserPrincipalName, UserId, GroupDisplayName, GroupId, RoleDisplayName, DirectoryScopeId, FindingSeverity |
        ConvertTo-Csv -NoTypeInformation
)
$manualReviewCsv = $manualReviewCsvRows -join [Environment]::NewLine
$ruleEvaluationJson = if ($evaluationRecords.Count -gt 0) {
    $evaluationRecords | ConvertTo-Json -Depth 12
}
else {
    '[]'
}
$ruleEvaluationCsv = @(
    $evaluationRecords |
        Select-Object FindingId, UserPrincipalName, RoleDisplayName, Severity, ReviewState, Decision, IncludeInRemediation, DisableUser, MatchedRuleId, MatchedRuleMode, MatchedRuleAction, ExpiredRuleCount |
        ConvertTo-Csv -NoTypeInformation
) -join [Environment]::NewLine

Write-FileUtf8 -Path $manifestPath -Content $manifestJson
Write-FileUtf8 -Path $summaryPath -Content $summary
Write-FileUtf8 -Path $manualReviewJsonPath -Content $manualReviewJson
Write-FileUtf8 -Path $manualReviewCsvPath -Content $manualReviewCsv
Write-FileUtf8 -Path $ruleEvaluationJsonPath -Content $ruleEvaluationJson
Write-FileUtf8 -Path $ruleEvaluationCsvPath -Content $ruleEvaluationCsv

Write-Info ("Remediation manifest written to {0}" -f $manifestPath)
Write-Info ("Remediation summary written to {0}" -f $summaryPath)
Write-Info ("Manual review artifacts written to {0} and {1}" -f $manualReviewJsonPath, $manualReviewCsvPath)
Write-Info ("Rule evaluation artifacts written to {0} and {1}" -f $ruleEvaluationJsonPath, $ruleEvaluationCsvPath)
