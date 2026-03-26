<#
.SYNOPSIS
    ValidationEngine.ps1 — machine entry point. Connects all collectors and processors.
    Handles PreProvision (payload-based), PostProvision (tenant verification),
    FullScan, and DriftOnly execution modes.

.DESCRIPTION
    Execution order:
        1. IdentityCollector       → identity snapshot (Graph)
        2. RbacCollector           → RBAC snapshot (Azure, all subscriptions)
        3. IdentityRuleProcessor   → Identity / Access / Architecture / Hygiene findings
        4. RbacRuleProcessor       → RBAC findings
        5. CorrelationRuleProcessor → cross-plane findings
        6. RiskClassifier          → aggregate + classify
        7. ReportGenerator         → output + export

    This is the only file that calls across layer boundaries.

    HOW POSTPROVISION WORKS:
        PostProvision is not a separate -Mode value. The HTTP trigger in
        run.ps1 maps a PostProvision request to -Mode PreProvision -TargetUserId.
        The engine then fetches the real Entra object via Get-UserSnapshot (3 Graph
        calls, O(1)) and evaluates it against the same rule set. The difference from
        a standard PreProvision run is that the user already exists in the tenant,
        so the snapshot reflects actual provisioned state rather than a synthetic payload.

.PARAMETER Mode
    PreProvision — single user evaluation. Accepts either -IdentityPayload (user does
                   not exist yet, synthetic snapshot) or -TargetUserId (user exists,
                   live snapshot). Both pre-provision checks and post-provision
                   verification run under this mode.
    FullScan     — all users, all rules, full metrics across the entire tenant.
    DriftOnly    — Architecture / RBAC / Correlation categories only, fast scan.

.PARAMETER RulesPath
    Path to Rules.json. Defaults to .\Rules.json

.PARAMETER TargetUserId
    Entra ID Object ID of the user to evaluate. Used in two scenarios:
        PreProvision — passed directly by the JML engine for a targeted single-user check.
        PostProvision — run.ps1 maps a PostProvision HTTP request to PreProvision + TargetUserId,
                        so this parameter is also how post-provision tenant verification is triggered.

.PARAMETER TargetDisplayName
    Optional display name used in PreProvision console output.

.PARAMETER OutputDir
    Export directory. Defaults to .\Output\

.PARAMETER ErrorLogPath
    Optional CSV path for collection failures across all collectors.

.PARAMETER ExportCsv / ExportJson
    Export findings to CSV or JSON (FullScan / DriftOnly only).

.PARAMETER StoreDriftState
    Saves the FullScan result for drift comparison on the next run.

.PARAMETER ResolveMfa
    Check MFA per user during identity collection. Adds latency (optional)

.PARAMETER SubscriptionFilter
    Limit RBAC collection to specific subscription IDs. Empty = all.

.EXAMPLE
    .\ValidationEngine.ps1 -Mode PreProvision -TargetUserId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    .\ValidationEngine.ps1 -Mode FullScan -ExportCsv -ExportJson -StoreDriftState -ResolveMfa
    .\ValidationEngine.ps1 -Mode DriftOnly -ExportJson
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('PreProvision', 'FullScan', 'DriftOnly')]
    [string] $Mode,

    [Parameter()] [string]   $RulesPath          = (Join-Path $PSScriptRoot 'Rules.json'),
    [Parameter()] [string]   $TargetUserId        = '',
    [Parameter()] [string]   $TargetDisplayName   = '',
    [Parameter()] [string]   $IdentityPayload     = '',
    [Parameter()] [string]   $OutputDir           = (Join-Path $PSScriptRoot 'Output'),
    [Parameter()] [string]   $ErrorLogPath        = '',
    [Parameter()] [switch]   $ExportCsv,
    [Parameter()] [switch]   $ExportJson,
    [Parameter()] [switch]   $StoreDriftState,
    [Parameter()] [switch]   $ResolveMfa,
    [Parameter()] [string[]] $SubscriptionFilter  = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


# Source all layers
$root = $PSScriptRoot

. (Join-Path $root 'Collectors' 'IDCollector.ps1')
. (Join-Path $root 'Collectors' 'RbacCollector.ps1')
. (Join-Path $root 'Rules' 'FindingSchema.ps1')
. (Join-Path $root 'Rules' 'IDRuleProcessor.ps1')
. (Join-Path $root 'Rules' 'RbacRuleProcessor.ps1')
. (Join-Path $root 'Rules' 'CorrelationRuleProcessor.ps1')
. (Join-Path $root 'Reporting' 'RiskClassifier.ps1')
. (Join-Path $root 'Reporting' 'ReportGen.ps1')


# Validate
if ($Mode -eq 'PreProvision') {
    $hasTargetUser    = -not [string]::IsNullOrWhiteSpace($TargetUserId)
    $hasPayload       = -not [string]::IsNullOrWhiteSpace($IdentityPayload)

    if (-not $hasTargetUser -and -not $hasPayload) {
        throw 'ValidationEngine: PreProvision mode requires either -TargetUserId or -IdentityPayload.'
    }
}

if (-not (Test-Path -LiteralPath $RulesPath)) {
    throw "ValidationEngine: Rules file not found at '$RulesPath'."
}

Write-Verbose "ValidationEngine: [$Mode] starting at $(Get-Date -Format 'o')"


# Load rules once — shared across all processors


$rulesDocument = Get-Content -LiteralPath $RulesPath -Raw | ConvertFrom-Json


# STEP 1 — Identity collection

Write-Verbose 'ValidationEngine: [1/5] Collecting identity data...'

# Build the authoritative privileged group name list from the entitlement model.
# These are exact display names of groups whose tier is in _privilegedTiers (e.g. Exec_Team).
# This is passed separately from PrivilegedGroupPatterns, which uses regex and is a catch-all
# for groups not in the model (legacy naming like Admin, Tier0, etc.).
# Without this exact list, Exec_Team and HR_Mangers would not be flagged as privileged
# because their display names don't contain the tier string 'Manager'.

$privilegedGroupNames = [System.Collections.Generic.List[string]]::new()
if ($rulesDocument.entitlementModel -and $rulesDocument.entitlementModel.groups) {
    $privTierSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$rulesDocument.entitlementModel._privilegedTiers,
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($prop in $rulesDocument.entitlementModel.groups.PSObject.Properties) {
        if ($privTierSet.Contains($prop.Value.tier)) {
            $privilegedGroupNames.Add($prop.Name)
        }
    }
}


# Route to the correct collector based on mode and parameters.
#
#   PreProvision + IdentityPayload  → synthetic snapshot, zero Graph calls
#                                     user does not exist in Entra yet
#
#   PreProvision + TargetUserId     → Get-UserSnapshot: 3 Graph calls, O(1)
#                                     used for PostProvision verification
#                                     and targeted pre-provision checks
#
#   FullScan / DriftOnly            → Get-IdentitySnapshot: full tenant scan
#                                     fetches all users, groups, memberships

if ($Mode -eq 'PreProvision' -and -not [string]::IsNullOrWhiteSpace($IdentityPayload)) {

    # Payload path, user does not exist yet, build synthetic snapshot
    $payloadObject    = $IdentityPayload | ConvertFrom-Json
    $identitySnapshot = New-IdentitySnapshotFromPayload -Payload $payloadObject
    $TargetUserId     = $identitySnapshot.Users[0].UserId

} elseif ($Mode -eq 'PreProvision' -and -not [string]::IsNullOrWhiteSpace($TargetUserId)) {

    # Targeted path, fetch only this user, their memberships, and licenses.
    # O(1) regardless of tenant size. Used for PostProvision verification.
    try {
        $identitySnapshot = Get-UserSnapshot -UserId $TargetUserId
    }
    catch {
        $result = [PSCustomObject]@{
            EntityId      = $TargetUserId
            EntityType    = 'User'
            Decision      = 'Fail'
            BlockingCount = 1
            Reasons       = @("Could not fetch user from directory: $_")
            Findings      = @()
            Mode          = 'PreProvision'
            EvaluatedAt   = [datetime]::UtcNow.ToString('o')
        }
        Write-PreProvisionReport -ClassificationResult $result -TargetDisplayName $TargetDisplayName
        return $result
    }

} else {

    # Full tenant scan — FullScan and DriftOnly only
    $identityParams = @{
        PrivilegedGroupPatterns = @([string[]]$rulesDocument.entitlementModel._privilegedTiers + @('Admin', 'Tier0', 'Tier1'))
        PrivilegedGroupNames    = $privilegedGroupNames.ToArray()
        ErrorLogPath            = $ErrorLogPath
        ResolveMfa              = $ResolveMfa
    }
    $identitySnapshot = Get-IdentitySnapshot @identityParams
}

if ($identitySnapshot.Users.Count -eq 0) {
    if ($Mode -eq 'PreProvision') {
        $result = [PSCustomObject]@{
            EntityId      = $TargetUserId
            EntityType    = 'User'
            Decision      = 'Fail'
            BlockingCount = 1
            Reasons       = @('Target user not found in directory.')
            Findings      = @()
            Mode          = 'PreProvision'
            EvaluatedAt   = [datetime]::UtcNow.ToString('o')
        }
        Write-PreProvisionReport -ClassificationResult $result -TargetDisplayName $TargetDisplayName
        return $result
    }
    Write-Warning 'ValidationEngine: No users returned from IdentityCollector. Aborting.'
    return $null
}

Write-Verbose "ValidationEngine: $($identitySnapshot.Users.Count) users, $($identitySnapshot.Groups.Count) groups collected."


# STEP 2 — RBAC collection (skip for PreProvision — no subscription scan needed)

$rbacSnapshot = $null

if ($Mode -ne 'PreProvision') {
    Write-Verbose 'ValidationEngine: [2/5] Collecting RBAC data across all subscriptions...'
    $rbacSnapshot = Get-RbacSnapshot -ErrorLogPath $ErrorLogPath -SubscriptionFilter $SubscriptionFilter
    Write-Verbose "ValidationEngine: $($rbacSnapshot.RoleAssignments.Count) role assignments across $($rbacSnapshot.SubscriptionsEnumerated.Count) subscription(s)."
}
else {
    # Empty stub so downstream code doesn't null-check everywhere
    $rbacSnapshot = [PSCustomObject]@{
        RoleAssignments         = [System.Collections.Generic.List[PSCustomObject]]::new()
        SubscriptionsEnumerated = [System.Collections.Generic.List[PSCustomObject]]::new()
        CollectedAt             = [datetime]::UtcNow
    }
}


# STEP 3 — Rule evaluation (all three processors)


Write-Verbose 'ValidationEngine: [3/5] Running rule processors...'

$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

# Identity plane
# Explicitly type all findings variables — an empty List[PSCustomObject] returned from
# a function gets unwrapped to $null by PowerShell when assigned to an untyped variable.
# Typing the left-hand side forces PowerShell to keep the empty List intact.
[System.Collections.Generic.List[PSCustomObject]] $identityFindings =
    Invoke-IdentityRuleEngine -RulesDocument $rulesDocument -IdentitySnapshot $identitySnapshot
foreach ($f in $identityFindings) { $allFindings.Add($f) }
Write-Verbose "ValidationEngine: Identity processor → $($identityFindings.Count) finding(s)"

# RBAC plane (skip for PreProvision)
if ($Mode -ne 'PreProvision') {
    [System.Collections.Generic.List[PSCustomObject]] $rbacFindings =
        Invoke-RbacRuleEngine -RulesDocument $rulesDocument -RbacSnapshot $rbacSnapshot
    foreach ($f in $rbacFindings) { $allFindings.Add($f) }
    Write-Verbose "ValidationEngine: RBAC processor → $($rbacFindings.Count) finding(s)"

    # Correlation (requires both planes)
    [System.Collections.Generic.List[PSCustomObject]] $corrFindings =
        Invoke-CorrelationRuleEngine -RulesDocument $rulesDocument `
            -IdentitySnapshot $identitySnapshot -RbacSnapshot $rbacSnapshot
    foreach ($f in $corrFindings) { $allFindings.Add($f) }
    Write-Verbose "ValidationEngine: Correlation processor → $($corrFindings.Count) finding(s)"
}

Write-Verbose "ValidationEngine: Total findings before classification: $($allFindings.Count)"


# STEP 4 — Risk classification

Write-Verbose 'ValidationEngine: [4/5] Classifying risk...'

$classifyParams = @{ Mode = $Mode; Findings = $allFindings }

if ($Mode -eq 'PreProvision') {
    $classifyParams['TargetEntityId'] = $TargetUserId
}
else {
    # Start with all user IDs from the identity snapshot
    $allEntityIds = [System.Collections.Generic.List[string]]::new()
    foreach ($u in $identitySnapshot.Users) { $allEntityIds.Add($u.UserId) }

    # Add any Group or ServicePrincipal principals from RBAC findings that
    # aren't already in the list, these won't be in the identity snapshot
    # but must still receive a risk state so their findings aren't dropped
    $userIdSet = [System.Collections.Generic.HashSet[string]]::new(
        $allEntityIds, [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($f in $allFindings) {
        if ($f.EntityType -ne 'User' -and -not $userIdSet.Contains($f.EntityId)) {
            $allEntityIds.Add($f.EntityId)
            [void]$userIdSet.Add($f.EntityId)
        }
    }

    $classifyParams['AllEntityIds'] = $allEntityIds.ToArray()

    # Count privileged users here — identity snapshot is in scope, classifier is not.
    # IsPrivileged is set by Set-UserPrivilegeFlag in the collector based on group membership.
    # This is the only layer where both snapshot and findings exist simultaneously.
    $classifyParams['PrivilegedCount'] = @($identitySnapshot.Users | Where-Object { $_.IsPrivileged }).Count
}

$classificationResult = Invoke-RiskClassification @classifyParams


# Build enrichment lookup table — EntityId → human-readable context
# Used by the report layer to produce readable CSV/JSON output.
# Built here because this is the only point where identity snapshot,
# RBAC snapshot, membership map, and classification results all coexist.


$enrichmentMap = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)

if ($Mode -ne 'PreProvision') {

# Index group names by GroupId for fast membership resolution
$groupNameById = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($g in $identitySnapshot.Groups) {
    $groupNameById[$g.GroupId] = $g.DisplayName
}

# Index risk states by EntityId for fast join
$riskStateById = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($rs in $classificationResult.EntityRiskStates) {
    $riskStateById[$rs.EntityId] = $rs
}

# Resolve tier for a user: highest-privilege tier across all their groups
# based on the entitlementModel in Rules.json
$tierLookup = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
if ($rulesDocument.entitlementModel -and $rulesDocument.entitlementModel.groups) {
    foreach ($prop in $rulesDocument.entitlementModel.groups.PSObject.Properties) {
        $tierLookup[$prop.Name] = $prop.Value.tier
    }
}

$tierOrder = @{ 'Manager/Staff' = 4; 'Manager' = 3; 'Base/Staff' = 2; 'Base' = 1 }

foreach ($user in $identitySnapshot.Users) {

    # Resolve group memberships to display names
    $memberGroupNames = @()
    if ($identitySnapshot.MembershipMap.ContainsKey($user.UserId)) {
        $memberGroupNames = @(
            $identitySnapshot.MembershipMap[$user.UserId] |
            ForEach-Object { if ($groupNameById.ContainsKey($_)) { $groupNameById[$_] } } |
            Where-Object { $_ }
        )
    }

    # Resolve highest tier from group membership
    $highestTier   = 'Unknown'
    $highestOrder  = 0
    foreach ($gname in $memberGroupNames) {
        if ($tierLookup.ContainsKey($gname)) {
            $t = $tierLookup[$gname]
            $o = if ($tierOrder.ContainsKey($t)) { $tierOrder[$t] } else { 0 }
            if ($o -gt $highestOrder) { $highestOrder = $o; $highestTier = $t }
        }
    }

    # Risk state — may not exist if user has no findings (compliant users still in state list)
    $rs = if ($riskStateById.ContainsKey($user.UserId)) { $riskStateById[$user.UserId] } else { $null }

    $enrichmentMap[$user.UserId] = [PSCustomObject]@{
        UPN              = $user.UserPrincipalName
        DisplayName      = $user.DisplayName
        EntityType       = 'User'
        EmployeeType     = if ($user.EmployeeType)     { $user.EmployeeType     } else { '' }
        EmploymentStatus = if ($user.EmploymentStatus) { $user.EmploymentStatus } else { '' }
        IsPrivileged     = $user.IsPrivileged
        Tier             = $highestTier
        Groups           = ($memberGroupNames -join ' | ')
        ComplianceStatus  = if ($rs) { $rs.ComplianceStatus  } else { 'Compliant' }
        RiskLevel         = if ($rs) { $rs.RiskLevel         } else { 'None'      }
        RiskScore         = if ($rs) { $rs.RiskScore         } else { 0           }
        RiskScoreRaw      = if ($rs) { $rs.RiskScoreRaw      } else { 0           }
        RiskDensity       = if ($rs) { $rs.RiskDensity       } else { 0           }
        HygieneIssueCount = if ($rs) { $rs.HygieneIssueCount } else { 0           }
        RecommendedAction = if ($rs) { $rs.RecommendedAction } else { 'None'      }
    }
}

# ServicePrincipal / Group entities from RBAC findings.
# RBAC assignments carry PrincipalName (DisplayName from ARM) — use it for readability
# instead of falling back to the raw EntityId (ObjectId GUID) in the CSV.
$rbacPrincipalNames = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($ra in $rbacSnapshot.RoleAssignments) {
    if (-not $rbacPrincipalNames.ContainsKey($ra.PrincipalId) -and
        -not [string]::IsNullOrWhiteSpace($ra.PrincipalName)) {
        $rbacPrincipalNames[$ra.PrincipalId] = $ra.PrincipalName
    }
}

foreach ($rs in $classificationResult.EntityRiskStates) {
    if (-not $enrichmentMap.ContainsKey($rs.EntityId)) {
        $principalName = if ($rbacPrincipalNames.ContainsKey($rs.EntityId)) {
            $rbacPrincipalNames[$rs.EntityId]
        } else {
            $rs.EntityId   # GUID fallback — only when ARM has no display name
        }

        $enrichmentMap[$rs.EntityId] = [PSCustomObject]@{
            UPN               = $principalName   # SPs/Groups have no UPN — display name is most readable
            DisplayName       = $principalName
            EntityType        = $rs.EntityType
            EmployeeType      = ''               # not applicable for non-user entities
            EmploymentStatus  = ''
            IsPrivileged      = $false
            Tier              = 'N/A'
            Groups            = ''
            ComplianceStatus  = $rs.ComplianceStatus
            RiskLevel         = $rs.RiskLevel
            RiskScore         = $rs.RiskScore
            RiskScoreRaw      = $rs.RiskScoreRaw
            RiskDensity       = $rs.RiskDensity
            HygieneIssueCount = $rs.HygieneIssueCount
            RecommendedAction = $rs.RecommendedAction
        }
    }
}
}

# STEP 5 — Report


Write-Verbose 'ValidationEngine: [5/5] Generating report...'

if ($Mode -eq 'PreProvision') {
    Write-PreProvisionReport -ClassificationResult $classificationResult -TargetDisplayName $TargetDisplayName
}
else {
    Write-GovernanceReport `
        -ClassificationResult $classificationResult `
        -OutputDir            $OutputDir `
        -ExportCsv:$ExportCsv `
        -ExportJson:$ExportJson `
        -StoreDriftState:$StoreDriftState `
        -EnrichmentMap        $enrichmentMap
}

Write-Verbose 'ValidationEngine: Run complete.'
return $classificationResult