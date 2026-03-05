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

# Categories owned by this processor (identity-plane only)
$Script:IdentityCategories = @('Identity', 'Access', 'Architecture', 'Hygiene')

# ---------------------------------------------------------------------------
# Evaluate-EmploymentAlignment
# Identity hygiene & lifecycle governance checks:
#   - UPN naming standards
#   - Employment status validation
#   - Terminated users with residual access
#   - Job title vs group membership conflicts
#   - Inactivity thresholds
#   - Password age compliance
# ---------------------------------------------------------------------------

function Evaluate-EmploymentAlignment {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Rule,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $p        = $Rule.parameters
    $now      = [datetime]::UtcNow

    # ── Joiner-scoped rules ───────────────────────────────────────────────────
    # JOIN rules apply the same checks as their non-JOIN counterparts but are
    # scoped to users whose CreatedDateTime is within the joiner window.
    # This lets the engine catch provisioning errors at point-of-join rather
    # than surfacing them only in FullScan hygiene cycles.
    # joinerCheck = false means evaluate all users (standard rule behaviour).
    $isJoinerRule   = $p.PSObject.Properties['joinerCheck'] -and $p.joinerCheck
    $joinerWindowDays = if ($p.PSObject.Properties['joinerWindowDays']) { [int]$p.joinerWindowDays } else { 30 }

    foreach ($user in $IdentitySnapshot.Users) {

        # Gate joiner rules to users created within the onboarding window.
        # Users with null CreatedDateTime are included — missing creation date
        # on a new account is itself a data quality issue worth catching.
        if ($isJoinerRule) {
            $isNewJoiner = $null -eq $user.CreatedDateTime -or
                ($now - [datetime]$user.CreatedDateTime).TotalDays -le $joinerWindowDays
            if (-not $isNewJoiner) { continue }
        }

        # Validate UPN naming standard
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

        # Validate employment status field consistency
        if ($p.PSObject.Properties['requiredValue'] -and $p.field -eq 'EmploymentStatus') {
            $status = $user.EmploymentStatus

            # Unknown employment — emits distinct message when unknownTrigger is set.
            # IDENT-003 owns this branch entirely. IDENT-004 has been removed.
            # continue ensures only one finding fires per user — Unknown takes precedence
            # over the generic not-Active check so the message stays precise.
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

            # Employment status mismatch (non-Active, non-Unknown)
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

        # Terminated users still holding group memberships
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

        # Job title conflicts with forbidden group memberships
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

        # Account inactivity threshold enforcement
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
                if ($daysSince -ge $p.maxInactiveDays) {  # -ge: day 180 itself meets the threshold
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

        # Password age policy enforcement
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

# ---------------------------------------------------------------------------
# Evaluate-PrivilegeDrift
# Privileged access governance:
#   - Disabled privileged accounts
#   - MFA enforcement for privileged identities
#   - Tier-0 isolation enforcement
#   - Mixed privilege memberships
#   - Admin account misuse (dual-use)
#   - Service accounts in interactive groups
# ---------------------------------------------------------------------------

function Evaluate-PrivilegeDrift {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Rule,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $p        = $Rule.parameters

    # Build privileged group ID set once
    $privGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $IdentitySnapshot.Groups) {
        $isPriv = $g.IsPrivileged
        if ($p.PSObject.Properties['tier0GroupPatterns']) {
            $isPriv = $isPriv -or ($p.tier0GroupPatterns | Where-Object { $g.DisplayName -match $_ })
        }
        if ($isPriv) { [void]$privGroupIds.Add($g.GroupId) }
    }

    foreach ($user in $IdentitySnapshot.Users) {
        $userGroupIds     = @()
        if ($IdentitySnapshot.MembershipMap.ContainsKey($user.UserId)) {
            $userGroupIds = $IdentitySnapshot.MembershipMap[$user.UserId]
        }
        $userPrivGroupIds = @($userGroupIds | Where-Object { $privGroupIds.Contains($_) })

        # Disabled account in privileged group
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

        # MFA not registered on privileged account
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

        # Tier 0 isolation — non-admin account in Tier 0 group
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

        # Mixed privileged + standard membership
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

        # Admin account used in standard groups (dual-use)
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

        # Service account in interactive user group
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

# ---------------------------------------------------------------------------
# Evaluate-EntitlementModel
# Enforces declarative entitlement model from Rules.json:
#   ENT-001 Employment mismatch (non-privileged)
#   ENT-002 Employment mismatch in privileged tier (blocking)
#   ENT-003 Group not defined in entitlement model (unmanaged)
# ---------------------------------------------------------------------------

function Evaluate-EntitlementModel {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Rule,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot,
        [Parameter(Mandatory)] [PSCustomObject] $RulesDocument
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $p        = $Rule.parameters

    $model = $RulesDocument.entitlementModel
    if ($null -eq $model -or $null -eq $model.groups) {
        Write-Debug 'Evaluate-EntitlementModel: No entitlementModel.groups in rules document.'
        return $findings
    }

    # Case-insensitive group name -> policy lookup
    $modelLookup = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($prop in $model.groups.PSObject.Properties) {
        $modelLookup[$prop.Name] = $prop.Value
    }

    $privilegedTiers = @()
    if ($model.PSObject.Properties['_privilegedTiers']) { $privilegedTiers = $model._privilegedTiers }

    # GroupId -> DisplayName for fast lookup
    $groupById = @{}
    foreach ($g in $IdentitySnapshot.Groups) { $groupById[$g.GroupId] = $g.DisplayName }

    foreach ($user in $IdentitySnapshot.Users) {
        $userGroupIds = @()
        if ($IdentitySnapshot.MembershipMap.ContainsKey($user.UserId)) {
            $userGroupIds = $IdentitySnapshot.MembershipMap[$user.UserId]
        }
        if ($userGroupIds.Count -eq 0) { continue }

        # ── Null EmployeeType guard ──────────────────────────────────────────
        # If EmployeeType is missing, entitlement validation cannot be performed.
        # Emit a finding rather than silently skipping — incomplete HR data is
        # itself a policy violation because membership cannot be validated.
        # Normalise EmployeeType from Azure AD — trim whitespace, lowercase hyphen variants.
        # Azure AD / HR sync frequently produces: 'Full-Time ', 'Fulltime ', 'FULL-TIME'.
        # Canonical values in Rules.json are: 'Full-time', 'Intern', 'Contractor'.
        $employmentType = ($user.EmployeeType ?? '').Trim()
        $employmentType = switch -Regex ($employmentType.ToLower()) {
            '^full.?time$' { 'Full-time'  }
            '^intern$'     { 'Intern'     }
            '^contractor$' { 'Contractor' }
            default        { $employmentType }   # preserve unknown values for the finding message
        }
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

        # ── ENT-003: collect ALL unmanaged groups first, emit ONE finding ────
        # Emitting one finding per unmanaged group causes score inflation.
        # A user in 6 unmanaged groups has ONE policy violation, not six.
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

        # ── ENT-001 / ENT-002: per-group employment policy checks ────────────
        foreach ($gid in $userGroupIds) {
            if (-not $groupById.ContainsKey($gid)) { continue }
            $groupName = $groupById[$gid]
            if (-not $modelLookup.ContainsKey($groupName)) { continue }

            $policy    = $modelLookup[$groupName]
            $groupTier = $policy.tier
            $allowedTypes      = @($policy.allowedEmployment)
            $isPrivTier        = $privilegedTiers -contains $groupTier
            $employmentMismatch = $allowedTypes -notcontains $employmentType

            # ENT-002: employment mismatch in a privileged-tier group (blocking)
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

            # ENT-001: employment mismatch in a standard group (non-blocking)
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

# ---------------------------------------------------------------------------
# Dispatch table — maps rule.type to evaluator functions.
# Allows Rules.json to select logic dynamically without code changes.
# ---------------------------------------------------------------------------

$Script:IdentityDispatch = @{
    'Evaluate-EmploymentAlignment' = { param($r, $s, $doc) Evaluate-EmploymentAlignment -Rule $r -IdentitySnapshot $s }
    'Evaluate-PrivilegeDrift'      = { param($r, $s, $doc) Evaluate-PrivilegeDrift      -Rule $r -IdentitySnapshot $s }
    'Evaluate-EntitlementModel'    = { param($r, $s, $doc) Evaluate-EntitlementModel    -Rule $r -IdentitySnapshot $s -RulesDocument $doc }
}

# ---------------------------------------------------------------------------
# PUBLIC orchestrator — executes all identity-plane rules and returns findings.
# ---------------------------------------------------------------------------

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

    # ── Suppression pass (shared) ─────────────────────────────────────────────
    # Reads suppressesOnMatch from Rules.json. Removes findings for rules that
    # are superseded by a higher-priority rule that fired on the same entity.
    $allFindings = Invoke-SuppressionPass -Findings $allFindings -RulesDocument $RulesDocument

    return $allFindings
}