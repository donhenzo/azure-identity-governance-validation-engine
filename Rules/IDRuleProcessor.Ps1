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

$Script:IdentityCategories = @('Identity', 'Access', 'Architecture', 'Hygiene', 'SoD')


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

function Evaluate-SoDConflict {
    <#
    .SYNOPSIS
        Evaluates group memberships against the SoD policy catalogue in sod_policies.json.

    .DESCRIPTION
        Implements the ANY_TO_ANY intersection model:
            A violation fires when an identity holds at least one group from set_a
            AND at least one group from set_b simultaneously.

        This is the PowerShell-native SoD evaluation. It reads the same
        sod_policies.json that the Python JML engine reads — single source of
        truth for conflict pairs. The intersection logic is duplicated here
        (four lines) so the validation engine has no HTTP or subprocess dependency
        on the Python runtime during FullScan or PostProvision passes.

        Block policies produce Critical/blocking findings.
        Warn policies produce High/non-blocking findings.

        This function runs in two contexts:
            FullScan    — scans all tenant users, catches existing violations
                          including manual assignments and pre-SoD drift.
            PostProvision — evaluates the specific provisioned identity
                           against actual Entra ID state.

    .PARAMETER Rule
        The SOD-EVAL-001 rule object from Rules.json.

    .PARAMETER IdentitySnapshot
        Output from Get-IdentitySnapshot (FullScan) or Get-UserSnapshot (PostProvision).

    .PARAMETER RulesDocument
        Parsed Rules.json. Not used directly — SoD policies come from sod_policies.json.
        Parameter kept for consistency with the dispatch table signature.

    .OUTPUTS
        List[PSCustomObject] — one ComplianceFinding per SoD violation per user.
        Multiple violations per user are all returned — evaluation never stops at first.

    .NOTES
        sod_policies.json is located next to the Rules.json that was loaded.
        The orchestrator sets $Script:RulesDocumentPath (the path to Rules.json),
        and this function reads the sibling sod_policies.json from the same folder.
        When that variable is not set (online/dev runs), it falls back to the
        engine root. This keeps each engagement folder fully self-contained.

        Only AnyToAny mode is evaluated. Policies with other mode values are
        skipped with a debug message — consistent with the Python sod_loader
        which rejects unimplemented modes at load time.
    #>
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Rule,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot,
        [Parameter()] [PSCustomObject] $RulesDocument = $null
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $p        = $Rule.parameters

    # sod_policies.json always lives next to the Rules.json that was loaded.
    # ValidationEngine.ps1 sets $Script:RulesDocumentPath so it can find it.
    # Fallback to engine root for callers that didn't pass it (online/dev).
    if ($Script:RulesDocumentPath) {
        $sodPoliciesPath = Join-Path (Split-Path $Script:RulesDocumentPath -Parent) 'sod_policies.json'
    }
    else {
        $sodPoliciesPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'sod_policies.json'
    }

    if (-not (Test-Path $sodPoliciesPath)) {
        Write-Warning "Evaluate-SoDConflict: sod_policies.json not found at '$sodPoliciesPath'. SoD evaluation skipped."
        return ,$findings
    }

    try {
        $sodDocument = Get-Content $sodPoliciesPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        Write-Warning "Evaluate-SoDConflict: Failed to parse sod_policies.json — $_. SoD evaluation skipped."
        return ,$findings
    }

    $sodPolicies = $sodDocument.policies
    if (-not $sodPolicies -or $sodPolicies.Count -eq 0) {
        Write-Debug 'Evaluate-SoDConflict: No policies found in sod_policies.json.'
        return ,$findings
    }

    # Severity and weight for warn-level violations — read from rule parameters
    # so they can be tuned in Rules.json without touching this function.
    $warnSeverity = $p.PSObject.Properties['warnSeverity'] ? $p.warnSeverity : 'High'
    $warnWeight   = $p.PSObject.Properties['warnWeight']   ? [int]$p.warnWeight : 70

    # Build a display name → group ID map for efficient membership lookups.
    # The SoD policy sets contain GUIDs. The snapshot membership map is keyed
    # by group ID. We need to resolve set_a / set_b GUIDs against the user's
    # memberOf GUIDs directly — no display name lookup needed.
    # The set entries in sod_policies.json are GUIDs, matching the snapshot.

    # Evaluate each user
    foreach ($user in $IdentitySnapshot.Users) {

        # Payload scans have no real group memberships — SoD can only evaluate
        # actual tenant state. Skip payload scans entirely.
        if ($IdentitySnapshot.IsPayloadScan) { continue }

        $userGroupIds = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        if ($IdentitySnapshot.MembershipMap.ContainsKey($user.UserId)) {
            foreach ($gid in $IdentitySnapshot.MembershipMap[$user.UserId]) {
                [void]$userGroupIds.Add($gid)
            }
        }

        if ($userGroupIds.Count -eq 0) { continue }

        # Evaluate each SoD policy
        foreach ($policy in $sodPolicies) {

            # Only ANY_TO_ANY is implemented. Skip other modes with a debug
            # message — consistent with Python sod_loader behaviour.
            if ($policy.mode -ne 'AnyToAny') {
                Write-Debug "Evaluate-SoDConflict: Policy '$($policy.id)' uses mode '$($policy.mode)' — not yet implemented. Skipping."
                continue
            }

            # ANY_TO_ANY intersection:
            #   matched_a = groups the user holds that appear in set_a
            #   matched_b = groups the user holds that appear in set_b
            #   Violation = both non-empty
            $matchedA = @($policy.set_a | Where-Object { $userGroupIds.Contains($_) })
            $matchedB = @($policy.set_b | Where-Object { $userGroupIds.Contains($_) })

            if ($matchedA.Count -eq 0 -or $matchedB.Count -eq 0) { continue }

            # Resolve display names for the finding detail — more readable
            # than raw GUIDs in audit output.
            $conflictingNames = [System.Collections.Generic.List[string]]::new()
            $allConflicting   = @($matchedA) + @($matchedB)

            foreach ($gid in $allConflicting) {
                $displayName = $IdentitySnapshot.Groups |
                    Where-Object { $_.GroupId -eq $gid } |
                    Select-Object -ExpandProperty DisplayName -First 1
                if ($displayName) {
                    $conflictingNames.Add($displayName)
                } else {
                    # GUID not found in snapshot groups — use raw ID
                    $conflictingNames.Add($gid)
                }
            }

            $conflictDetail = $conflictingNames -join ', '

            # Block policies → Critical/blocking finding
            # Warn policies → High/non-blocking finding
            $isBlock   = $policy.action -eq 'Block'
            $severity  = if ($isBlock) { 'Critical' } else { $warnSeverity }
            $weight    = if ($isBlock) { $Rule.weight } else { $warnWeight }
            $blocking  = $isBlock

            $detail = "[$($policy.id)] $($policy.name) — conflicting groups: $conflictDetail"

            if ($policy.compensating_control) {
                $detail += " — Compensating control: $($policy.compensating_control)"
            }

            $findings.Add((New-ComplianceFinding `
                -EntityId   $user.UserId `
                -EntityType 'User' `
                -RuleId     "SOD-EVAL-001/$($policy.id)" `
                -Category   $Rule.category `
                -Severity   $severity `
                -Weight     $weight `
                -Blocking   $blocking `
                -Details    $detail))

            Write-Warning "SoD violation detected — user=$($user.UserId), policy=$($policy.id) ($($policy.name)), action=$($policy.action), conflicting=$conflictDetail"
        }
    }

    return ,$findings
}


#  PreProvision payload check (before user is created)
# Check: is this combination of employment type + job title allowed to proceed at all?
function Evaluate-PayloadEntitlementPolicy {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Rule,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot,
        [Parameter()] [PSCustomObject] $RulesDocument = $null
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $p        = $Rule.parameters

    foreach ($user in $IdentitySnapshot.Users) {

        # Only meaningful on payload scans — real users already have group memberships
        # which are evaluated by ENT-001/ENT-002 instead.
        if (-not $IdentitySnapshot.IsPayloadScan) { continue }

        $employmentType = ($user.EmployeeType ?? '').Trim()
        $jobTitle       = ($user.JobTitle ?? '').Trim()

        $isRestrictedType = $p.restrictedEmploymentTypes -contains $employmentType
        $isManagerRole    = $p.restrictedJobTitlePatterns |
                            Where-Object { $jobTitle -match $_ }

        if ($isRestrictedType -and $isManagerRole) {
            $findings.Add((New-ComplianceFinding `
                -EntityId   $user.UserId `
                -EntityType 'User' `
                -RuleId     $Rule.id `
                -Category   $Rule.category `
                -Severity   $Rule.severity `
                -Weight     $Rule.weight `
                -Blocking   $Rule.blocking `
                -Details    "Employment type '$employmentType' is not permitted for Manager-tier role '$jobTitle'. Contractors and Interns cannot be provisioned into management positions."))
        }
    }

    return ,$findings
}


function Evaluate-PimEligibility {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Rule,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot,
        [Parameter()] [PSCustomObject] $RulesDocument = $null
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Skip on payload scans — PIM schedules cannot exist before provisioning
    if ($IdentitySnapshot.IsPayloadScan) { return ,$findings }

    # Skip if PIM data was not collected — non-P2 tenant or missing permission
    $hasPimData = $IdentitySnapshot.PSObject.Properties['PimSchedules'] -and
                  $null -ne $IdentitySnapshot.PimSchedules
    if (-not $hasPimData) { return ,$findings }

    foreach ($user in $IdentitySnapshot.Users) {

        $userPimSchedules = @(
            $IdentitySnapshot.PimSchedules |
            Where-Object { $_.PrincipalId -eq $user.UserId }
        )

        if ($userPimSchedules.Count -eq 0) { continue }

        # ENT-002 handles the blocking check at entitlement level.
        # PIM-001 is a verification — confirms eligibility was assigned.
        # Blocking = false because PIM schedule propagation can lag post-provision.
        $findings.Add((New-ComplianceFinding `
            -EntityId   $user.UserId `
            -EntityType 'User' `
            -RuleId     $Rule.id `
            -Category   $Rule.category `
            -Severity   'Low' `
            -Weight     15 `
            -Blocking   $false `
            -Details    "PIM eligibility schedules confirmed for user — $($userPimSchedules.Count) active schedule(s) found."))
    }

    return ,$findings
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
        '^(employee|full.?time)$' { 'Employee'   }   # accept both during transition
        '^intern$'                { 'Intern'     }
        '^contractor$'            { 'Contractor' }
        default                   { $employmentType }
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
    'Evaluate-EmploymentAlignment'      = { param($r, $s, $doc) Evaluate-EmploymentAlignment      -Rule $r -IdentitySnapshot $s }
    'Evaluate-PrivilegeDrift'           = { param($r, $s, $doc) Evaluate-PrivilegeDrift           -Rule $r -IdentitySnapshot $s -RulesDocument $doc }
    'Evaluate-EntitlementModel'         = { param($r, $s, $doc) Evaluate-EntitlementModel         -Rule $r -IdentitySnapshot $s -RulesDocument $doc }
    'Evaluate-PayloadEntitlementPolicy' = { param($r, $s, $doc) Evaluate-PayloadEntitlementPolicy -Rule $r -IdentitySnapshot $s -RulesDocument $doc }
    'Evaluate-PimEligibility'           = { param($r, $s, $doc) Evaluate-PimEligibility           -Rule $r -IdentitySnapshot $s -RulesDocument $doc }
    'Evaluate-SoDConflict' = { param($r, $s, $doc) Evaluate-SoDConflict -Rule $r -IdentitySnapshot $s -RulesDocument $doc }
}


function Invoke-IdentityRuleEngine {
    <#
    .SYNOPSIS
        Evaluates all Identity/Access/Architecture/Hygiene/SoD rules against the identity snapshot.
    .PARAMETER RulesDocument
        Parsed Rules.json object (pass the result of ConvertFrom-Json, not the path).
    .PARAMETER IdentitySnapshot
        Output from Get-IdentitySnapshot, New-IdentitySnapshotFromCsv, or Get-UserSnapshot.
    .PARAMETER RulesDocumentPath
        Optional. Path to the Rules.json file on disk. Used by Evaluate-SoDConflict
        to find sod_policies.json in the same folder (per-engagement layout).
        Leave empty for online/dev runs — SoD falls back to the engine root.
    .OUTPUTS
        List[PSCustomObject] — all findings from identity-plane rules
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $RulesDocument,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot,
        [Parameter()]          [string]         $RulesDocumentPath = ''
    )

    # Stash the rules file location so Evaluate-SoDConflict can resolve
    # sod_policies.json next to it (engagement folder layout).
    $Script:RulesDocumentPath = $RulesDocumentPath

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

    return ,$allFindings
}