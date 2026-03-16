<#
.SYNOPSIS
    IDRuleProcessor.ps1 — Evaluates identity-plane rules from Rules.json.
.DESCRIPTION
    Reads rules where category is: Identity | Access | Architecture | Hygiene
    Operates only on the IdentitySnapshot from IDCollector.
    No Azure/RBAC data touched here.
    Returns a flat list of ComplianceFinding objects.
    No aggregation. No console output. No risk scoring.
.NOTES
    Dot-source FindingSchema.ps1 before calling Invoke-IdentityRuleEngine.
#>
Set-StrictMode -Version Latest

$Script:IdentityCategories = @('Identity', 'Access', 'Architecture', 'Hygiene')


function Evaluate-EmploymentAlignment {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Rule,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $p        = $Rule.parameters
    $now      = [datetime]::UtcNow

    # JOIN rules scope evaluation to recently created accounts only.
    # joinerCheck = false means the rule applies to all users regardless of age.
    $isJoinerRule     = $p.PSObject.Properties['joinerCheck'] -and $p.joinerCheck
    $joinerWindowDays = if ($p.PSObject.Properties['joinerWindowDays']) { [int]$p.joinerWindowDays } else { 30 }

    foreach ($user in $IdentitySnapshot.Users) {

        if ($isJoinerRule) {
            # Users with no CreatedDateTime are included — missing creation date on a new account is a data quality problem worth catching.
            $isNewJoiner = $null -eq $user.CreatedDateTime -or
                ($now - [datetime]$user.CreatedDateTime).TotalDays -le $joinerWindowDays
            if (-not $isNewJoiner) { continue }
        }

        # UPN format validation
        if ($p.PSObject.Properties['validationPattern'] -and $p.field -eq 'UserPrincipalName') {
            $upn = $user.UserPrincipalName
            if ([string]::IsNullOrWhiteSpace($upn) -or $upn -notmatch $p.validationPattern) {
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "UPN '$upn' is missing or does not match required format."))
            }
            continue
        }

        # Employment status check — expects Active
        if ($p.PSObject.Properties['requiredValue'] -and $p.field -eq 'EmploymentStatus') {
            $status = $user.EmploymentStatus

            # Unknown is treated separately so the finding message is precise about the cause.
            # Both Unknown and non-Active are policy violations but for different reasons.
            if ($p.PSObject.Properties['unknownTrigger'] -and $p.unknownTrigger -and $status -eq 'Unknown') {
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "Employment status could not be determined (resolved as 'Unknown'). Verify HR system sync."))
                continue
            }

            if ($status -ne $p.requiredValue) {
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "Employment status is '$status'; expected '$($p.requiredValue)'."))
            }
            continue
        }

        # Terminated users who still have group memberships
        if ($p.PSObject.Properties['terminatedStatuses']) {
            if ($p.terminatedStatuses -contains $user.EmploymentStatus) {
                $userGroupIds = @()
                if ($IdentitySnapshot.MembershipMap.ContainsKey($user.UserId)) {
                    $userGroupIds = $IdentitySnapshot.MembershipMap[$user.UserId]
                }
                if ($userGroupIds.Count -gt 0) {
                    $groupNames = ($IdentitySnapshot.Groups |
                        Where-Object { $userGroupIds -contains $_.GroupId } |
                        Select-Object -ExpandProperty DisplayName) -join ', '
                    $findings.Add((New-ComplianceFinding `
                        -EntityId   $user.UserId `
                        -EntityType 'User' `
                        -RuleId     $Rule.id `
                        -Category   $Rule.category `
                        -Severity   $Rule.severity `
                        -Weight     $Rule.weight `
                        -Blocking   $Rule.blocking `
                        -Details    "Account status '$($user.EmploymentStatus)' but still in groups: $groupNames"))
                }
            }
            continue
        }

        # Job title conflicts — certain titles should never appear in certain groups
        if ($p.PSObject.Properties['jobTitlePatterns'] -and $p.PSObject.Properties['forbiddenGroupPatterns']) {
            $titleMatch = $p.jobTitlePatterns | Where-Object { $user.JobTitle -and $user.JobTitle -match $_ }
            if ($titleMatch) {
                $userGroupIds = @()
                if ($IdentitySnapshot.MembershipMap.ContainsKey($user.UserId)) {
                    $userGroupIds = $IdentitySnapshot.MembershipMap[$user.UserId]
                }
                $violatingGroups = $IdentitySnapshot.Groups | Where-Object {
                    $gid = $_.GroupId; $gName = $_.DisplayName
                    ($userGroupIds -contains $gid) -and (
                        ($p.forbiddenGroupPatterns | Where-Object { $gName -match $_ }).Count -gt 0
                    )
                }
                if ($violatingGroups) {
                    $groupList = ($violatingGroups | Select-Object -ExpandProperty DisplayName) -join ', '
                    $findings.Add((New-ComplianceFinding `
                        -EntityId   $user.UserId `
                        -EntityType 'User' `
                        -RuleId     $Rule.id `
                        -Category   $Rule.category `
                        -Severity   $Rule.severity `
                        -Weight     $Rule.weight `
                        -Blocking   $Rule.blocking `
                        -Details    "Job title '$($user.JobTitle)' is not permitted in groups: $groupList"))
                }
            }
            continue
        }

        # Account inactivity — how long since last sign-in
        if ($p.PSObject.Properties['maxInactiveDays'] -and $p.field -eq 'LastSignInDateTime') {
            $lastSignIn = $user.LastSignInDateTime
            if ($null -eq $lastSignIn) {
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "No sign-in recorded. Exceeds $($p.maxInactiveDays)-day inactivity threshold."))
            }
            else {
                $daysSince = ($now - [datetime]$lastSignIn).Days
                if ($daysSince -ge $p.maxInactiveDays) {
                    $findings.Add((New-ComplianceFinding `
                        -EntityId   $user.UserId `
                        -EntityType 'User' `
                        -RuleId     $Rule.id `
                        -Category   $Rule.category `
                        -Severity   $Rule.severity `
                        -Weight     $Rule.weight `
                        -Blocking   $Rule.blocking `
                        -Details    "Last sign-in $daysSince days ago (threshold: $($p.maxInactiveDays)). Last: $lastSignIn"))
                }
            }
            continue
        }

        # Password age — how long since last password change
        if ($p.PSObject.Properties['maxAgeDays'] -and $p.field -eq 'LastPasswordChangeDateTime') {
            $lastChange = $user.LastPasswordChangeDateTime
            if ($null -ne $lastChange) {
                $ageDays = ($now - [datetime]$lastChange).Days
                if ($ageDays -gt $p.maxAgeDays) {
                    $findings.Add((New-ComplianceFinding `
                        -EntityId   $user.UserId `
                        -EntityType 'User' `
                        -RuleId     $Rule.id `
                        -Category   $Rule.category `
                        -Severity   $Rule.severity `
                        -Weight     $Rule.weight `
                        -Blocking   $Rule.blocking `
                        -Details    "Password last changed $ageDays days ago (threshold: $($p.maxAgeDays))."))
                }
            }
            continue
        }
    }

    return $findings
}


function Evaluate-PrivilegeDrift {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Rule,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot,

        # RulesDocument is needed to read the privileged flag on entitlement model groups.
        # Optional so existing callers that do not pass it continue to work.
        [Parameter()] [PSCustomObject] $RulesDocument = $null
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $p        = $Rule.parameters

    # Build the set of privileged group IDs using two sources:
    #
    # 1. IsPrivileged on the group snapshot — set by IDCollector based on _privilegedTiers.
    #    Catches groups whose tier is Manager or Manager/Staff.
    #
    # 2. The privileged flag in the entitlementModel — catches groups that are explicitly
    #    marked privileged regardless of tier. This is needed for groups like SG_Security_Core
    #    (tier: Base, privileged: true) that the tier check alone would miss.
    #
    # The union of both sources is the correct privileged group set.
    $entitlementPrivileged = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $RulesDocument -and $RulesDocument.PSObject.Properties['entitlementModel'] -and
        $null -ne $RulesDocument.entitlementModel.groups) {
        foreach ($prop in $RulesDocument.entitlementModel.groups.PSObject.Properties) {
            if ($prop.Value.PSObject.Properties['privileged'] -and $prop.Value.privileged -eq $true) {
                [void]$entitlementPrivileged.Add($prop.Name)
            }
        }
    }

    $privGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $IdentitySnapshot.Groups) {

        # A group is privileged if the snapshot says so OR if the entitlement model explicitly flags it.
        $isPriv = $g.IsPrivileged -or $entitlementPrivileged.Contains($g.DisplayName)

        if ($p.PSObject.Properties['tier0GroupPatterns']) {
            $isPriv = $isPriv -or ($p.tier0GroupPatterns | Where-Object { $g.DisplayName -match $_ })
        }
        if ($isPriv) { [void]$privGroupIds.Add($g.GroupId) }
    }

    foreach ($user in $IdentitySnapshot.Users) {

        $userGroupIds = @()
        if ($IdentitySnapshot.MembershipMap.ContainsKey($user.UserId)) {
            $userGroupIds = $IdentitySnapshot.MembershipMap[$user.UserId]
        }
        $userPrivGroupIds = @($userGroupIds | Where-Object { $privGroupIds.Contains($_) })

        # Disabled account that still holds privileged group memberships
        if ($p.PSObject.Properties['requireEnabled'] -and $p.scope -eq 'PrivilegedGroups') {
            if (-not $user.AccountEnabled -and $userPrivGroupIds.Count -gt 0) {
                $names = ($IdentitySnapshot.Groups |
                    Where-Object { $userPrivGroupIds -contains $_.GroupId } |
                    Select-Object -ExpandProperty DisplayName) -join ', '
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "Disabled account is in privileged group(s): $names"))
            }
            continue
        }

        # Privileged account with no MFA registered — the highest-risk hygiene gap
        if ($p.PSObject.Properties['requireMFA'] -and $p.scope -eq 'PrivilegedGroups') {
            $mfaOk = $user.PSObject.Properties['MfaRegistered'] -and $user.MfaRegistered -eq $true
            if ($userPrivGroupIds.Count -gt 0 -and -not $mfaOk) {
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "Privileged account has no MFA registration or MFA is not enforced."))
            }
            continue
        }

        # Tier-0 isolation — standard accounts should never appear in Tier-0 groups
        if ($p.PSObject.Properties['enforceTierIsolation'] -and $p.PSObject.Properties['tier0GroupPatterns']) {
            $tier0Groups = $IdentitySnapshot.Groups | Where-Object {
                $gid = $_.GroupId; $gName = $_.DisplayName
                ($userGroupIds -contains $gid) -and (
                    ($p.tier0GroupPatterns | Where-Object { $gName -match $_ }).Count -gt 0
                )
            }
            if ($tier0Groups) {
                $isAdminAccount = $user.UserPrincipalName -match '(adm_|admin\.|_admin|svc_)'
                if (-not $isAdminAccount) {
                    $names = ($tier0Groups | Select-Object -ExpandProperty DisplayName) -join ', '
                    $findings.Add((New-ComplianceFinding `
                        -EntityId   $user.UserId `
                        -EntityType 'User' `
                        -RuleId     $Rule.id `
                        -Category   $Rule.category `
                        -Severity   $Rule.severity `
                        -Weight     $Rule.weight `
                        -Blocking   $Rule.blocking `
                        -Details    "Non-admin account is in Tier 0 group(s): $names"))
                }
            }
            continue
        }

        # Mixed membership — account is simultaneously in privileged and standard groups.
        # This is a separation of duties concern; privileged identities should not share
        # a user account with day-to-day standard access.
        if ($p.PSObject.Properties['detectMixedMembership'] -and $p.detectMixedMembership) {
            $hasPriv    = $userPrivGroupIds.Count -gt 0
            $hasNonPriv = @($userGroupIds | Where-Object { -not $privGroupIds.Contains($_) }).Count -gt 0
            if ($hasPriv -and $hasNonPriv) {
                $privNames = ($IdentitySnapshot.Groups |
                    Where-Object { $userPrivGroupIds -contains $_.GroupId } |
                    Select-Object -ExpandProperty DisplayName) -join ', '
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "Account holds privileged and standard membership simultaneously. Privileged: $privNames"))
            }
            continue
        }

        # Admin account in standard groups — admin accounts should only be in privileged groups
        if ($p.PSObject.Properties['detectAdminAccountDualUse'] -and $p.detectAdminAccountDualUse) {
            $isAdmin = $p.PSObject.Properties['adminAccountPatterns'] -and (
                $p.adminAccountPatterns | Where-Object { $user.UserPrincipalName -match $_ }
            )
            if ($isAdmin) {
                $nonPrivGroups = $IdentitySnapshot.Groups | Where-Object {
                    ($userGroupIds -contains $_.GroupId) -and (-not $privGroupIds.Contains($_.GroupId))
                }
                if ($nonPrivGroups.Count -gt 0) {
                    $names = ($nonPrivGroups | Select-Object -ExpandProperty DisplayName) -join ', '
                    $findings.Add((New-ComplianceFinding `
                        -EntityId   $user.UserId `
                        -EntityType 'User' `
                        -RuleId     $Rule.id `
                        -Category   $Rule.category `
                        -Severity   $Rule.severity `
                        -Weight     $Rule.weight `
                        -Blocking   $Rule.blocking `
                        -Details    "Admin account '$($user.UserPrincipalName)' is also in standard groups: $names"))
                }
            }
            continue
        }

        # Service account in interactive user groups
        if ($p.PSObject.Properties['serviceAccountPatterns'] -and $p.PSObject.Properties['forbiddenGroupPatterns']) {
            $isSvc = $p.serviceAccountPatterns | Where-Object { $user.UserPrincipalName -match $_ }
            if ($isSvc) {
                $violating = $IdentitySnapshot.Groups | Where-Object {
                    $gid = $_.GroupId; $gName = $_.DisplayName
                    ($userGroupIds -contains $gid) -and (
                        ($p.forbiddenGroupPatterns | Where-Object { $gName -match $_ }).Count -gt 0
                    )
                }
                if ($violating.Count -gt 0) {
                    $names = ($violating | Select-Object -ExpandProperty DisplayName) -join ', '
                    $findings.Add((New-ComplianceFinding `
                        -EntityId   $user.UserId `
                        -EntityType 'User' `
                        -RuleId     $Rule.id `
                        -Category   $Rule.category `
                        -Severity   $Rule.severity `
                        -Weight     $Rule.weight `
                        -Blocking   $Rule.blocking `
                        -Details    "Service account '$($user.UserPrincipalName)' is in interactive group(s): $names"))
                }
            }
            continue
        }
    }

    return $findings
}


function Evaluate-EntitlementModel {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Rule,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot,
        [Parameter(Mandatory)] [PSCustomObject] $RulesDocument
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $p        = $Rule.parameters
    $model    = $RulesDocument.entitlementModel

    if ($null -eq $model -or $null -eq $model.groups) {
        Write-Debug 'Evaluate-EntitlementModel: No entitlementModel.groups in rules document.'
        return $findings
    }

    $modelLookup = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($prop in $model.groups.PSObject.Properties) {
        $modelLookup[$prop.Name] = $prop.Value
    }

    $privilegedTiers = @()
    if ($model.PSObject.Properties['_privilegedTiers']) { $privilegedTiers = $model._privilegedTiers }

    $groupById = @{}
    foreach ($g in $IdentitySnapshot.Groups) { $groupById[$g.GroupId] = $g.DisplayName }

    foreach ($user in $IdentitySnapshot.Users) {

        $userGroupIds = @()
        if ($IdentitySnapshot.MembershipMap.ContainsKey($user.UserId)) {
            $userGroupIds = $IdentitySnapshot.MembershipMap[$user.UserId]
        }
        if ($userGroupIds.Count -eq 0) { continue }

        # Normalise EmployeeType — HR sync frequently produces variants like 'Full-Time ' or 'FULL-TIME'.
        # Canonical values in the entitlement model are: Full-time, Intern, Contractor.
        $employmentType = ($user.EmployeeType ?? '').Trim()
        $employmentType = switch -Regex ($employmentType.ToLower()) {
            '^full.?time$' { 'Full-time'  }
            '^intern$'     { 'Intern'     }
            '^contractor$' { 'Contractor' }
            default        { $employmentType }
        }

        # Missing EmployeeType means we cannot validate group membership against policy.
        # Emit a finding rather than silently skipping — incomplete HR data is itself a violation.
        if ([string]::IsNullOrWhiteSpace($employmentType)) {
            if ($p.PSObject.Properties['checkEmployment'] -or $p.PSObject.Properties['checkPrivilegedTier']) {
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   'High' `
                    -Weight     $Rule.weight `
                    -Blocking   $false `
                    -Details    "EmployeeType is null or empty — entitlement policy cannot be validated. HR data must be populated."))
            }
            continue
        }

        # ENT-003: one finding per user for all unmanaged groups combined.
        # Emitting one finding per group would inflate the score — being in 6 unmanaged groups
        # is still one policy violation, not six separate ones.
        if ($p.PSObject.Properties['unknownGroupAlert'] -and $p.unknownGroupAlert) {
            $unmanagedGroupNames = [System.Collections.Generic.List[string]]::new()
            foreach ($gid in $userGroupIds) {
                if (-not $groupById.ContainsKey($gid)) { continue }
                $gName = $groupById[$gid]
                if (-not $modelLookup.ContainsKey($gName)) {
                    $unmanagedGroupNames.Add($gName)
                }
            }
            if ($unmanagedGroupNames.Count -gt 0) {
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "Member of $($unmanagedGroupNames.Count) unmanaged group(s) not in entitlement model: $($unmanagedGroupNames -join ' | ')"))
            }
            continue
        }

        # ENT-001 / ENT-002: check each group the user belongs to against the entitlement model
        foreach ($gid in $userGroupIds) {
            if (-not $groupById.ContainsKey($gid)) { continue }
            $groupName = $groupById[$gid]
            if (-not $modelLookup.ContainsKey($groupName)) { continue }

            $policy    = $modelLookup[$groupName]
            $groupTier = $policy.tier

            $allowedTypes       = @($policy.allowedEmployment)
            $isPrivTier         = $privilegedTiers -contains $groupTier
            $employmentMismatch = $allowedTypes -notcontains $employmentType

            # ENT-002: employment type in a privileged tier group — always blocking
            if ($p.PSObject.Properties['checkPrivilegedTier'] -and $p.checkPrivilegedTier) {
                if ($isPrivTier -and $employmentMismatch) {
                    $findings.Add((New-ComplianceFinding `
                        -EntityId   $user.UserId `
                        -EntityType 'User' `
                        -RuleId     $Rule.id `
                        -Category   $Rule.category `
                        -Severity   $Rule.severity `
                        -Weight     $Rule.weight `
                        -Blocking   $Rule.blocking `
                        -Details    "Employment '$employmentType' not permitted in privileged group '$groupName' (Tier: $groupTier). Allowed: $($allowedTypes -join ', ')."))
                }
                continue
            }

            # ENT-001: employment type in a standard group — flagged for review, not blocking
            if ($p.PSObject.Properties['checkEmployment'] -and $p.checkEmployment) {
                if ($employmentMismatch -and -not $isPrivTier) {
                    $findings.Add((New-ComplianceFinding `
                        -EntityId   $user.UserId `
                        -EntityType 'User' `
                        -RuleId     $Rule.id `
                        -Category   $Rule.category `
                        -Severity   $Rule.severity `
                        -Weight     $Rule.weight `
                        -Blocking   $Rule.blocking `
                        -Details    "Employment '$employmentType' not in allowed list for '$groupName' (Tier: $groupTier). Allowed: $($allowedTypes -join ', '). Flagged for review."))
                }
                continue
            }
        }
    }

    return $findings
}


# Dispatch table — rule.type maps to the evaluator function that handles it.
# $doc (RulesDocument) is now passed to Evaluate-PrivilegeDrift so it can read
# the privileged flag from the entitlement model, not just the tier-based check.
$Script:IdentityDispatch = @{
    'Evaluate-EmploymentAlignment' = { param($r, $s, $doc) Evaluate-EmploymentAlignment -Rule $r -IdentitySnapshot $s }
    'Evaluate-PrivilegeDrift'      = { param($r, $s, $doc) Evaluate-PrivilegeDrift      -Rule $r -IdentitySnapshot $s -RulesDocument $doc }
    'Evaluate-EntitlementModel'    = { param($r, $s, $doc) Evaluate-EntitlementModel    -Rule $r -IdentitySnapshot $s -RulesDocument $doc }
}


function Invoke-IdentityRuleEngine {
    <#
    .SYNOPSIS
        Evaluates all Identity/Access/Architecture/Hygiene rules against the identity snapshot.
    .PARAMETER RulesDocument
        Parsed Rules.json object (pass the result of ConvertFrom-Json, not the path).
    .PARAMETER IdentitySnapshot
        Output from Get-IdentitySnapshot.
    .OUTPUTS
        List[PSCustomObject] — all findings from identity-plane rules
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $RulesDocument,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot
    )

    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $rules = $RulesDocument.rules | Where-Object { $Script:IdentityCategories -contains $_.category }

    foreach ($rule in $rules) {
        if (-not $Script:IdentityDispatch.ContainsKey($rule.type)) {
            Write-Debug "Invoke-IdentityRuleEngine: No handler for type '$($rule.type)' (rule: $($rule.id))"
            continue
        }
        try {
            $results = & $Script:IdentityDispatch[$rule.type] $rule $IdentitySnapshot $RulesDocument
            if ($results) { foreach ($f in $results) { $allFindings.Add($f) } }
        }
        catch {
            Write-Debug "Invoke-IdentityRuleEngine: Rule '$($rule.id)' threw: $_"
        }
    }

    # Remove findings that are superseded by a more specific rule firing on the same entity.
    # Suppression chains are declared in Rules.json — no hardcoded logic here.
    $allFindings = Invoke-SuppressionPass -Findings $allFindings -RulesDocument $RulesDocument

    return $allFindings
}