<#
.SYNOPSIS
    CorrelationRuleProcessor.ps1 — Evaluates rules that require BOTH identity and RBAC data.

.DESCRIPTION
    Executes rules where category = Correlation.
    Runs after IdentityRuleProcessor and RbacRuleProcessor.

    Correlation rules detect risk conditions that neither identity nor RBAC
    can detect alone.

.NOTES
    FindingSchema.ps1 must be dot-sourced before running CorrelationRuleEngine.
#>

Set-StrictMode -Version Latest

$Script:CorrelationCategories = @('Correlation')


function Build-CorrelationRbacIndex {
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [PSCustomObject] $RbacSnapshot)

    $index = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($a in $RbacSnapshot.RoleAssignments) {
        if (-not $index.ContainsKey($a.PrincipalId)) {
            $index[$a.PrincipalId] = [System.Collections.Generic.List[PSCustomObject]]::new()
        }
        $index[$a.PrincipalId].Add($a)
    }

    return $index
}


function Evaluate-CrossPlaneExposure {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Rule,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot,
        [Parameter(Mandatory)] [PSCustomObject] $RbacSnapshot,
        [Parameter(Mandatory)] [hashtable]      $RbacIndex,

        # RulesDocument is needed to read the privileged flag on entitlement model groups.
        # The user snapshot's IsPrivileged flag is set by the collector using tier-based logic only.
        # Groups like SG_Security_Core (tier: Base, privileged: true) would be missed without this.
        [Parameter()] [PSCustomObject] $RulesDocument = $null
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $p        = $Rule.parameters
    $now      = [datetime]::UtcNow

    # Build a set of group IDs that are explicitly marked privileged in the entitlement model.
    # This is used alongside $user.IsPrivileged to produce the correct privileged identity check
    # for CORR-001 and CORR-004. Without this, a Security Engineer in SG_Security_Core would
    # never trigger those rules because their tier is Base, not Manager.
    $entitlementPrivGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $RulesDocument -and $RulesDocument.PSObject.Properties['entitlementModel'] -and
        $null -ne $RulesDocument.entitlementModel.groups) {

        # Map display name to GroupId so we can look up by ObjectId later
        $groupDisplayToId = @{}
        foreach ($g in $IdentitySnapshot.Groups) {
            $groupDisplayToId[$g.DisplayName] = $g.GroupId
        }

        foreach ($prop in $RulesDocument.entitlementModel.groups.PSObject.Properties) {
            if ($prop.Value.PSObject.Properties['privileged'] -and $prop.Value.privileged -eq $true) {
                if ($groupDisplayToId.ContainsKey($prop.Name)) {
                    [void]$entitlementPrivGroupIds.Add($groupDisplayToId[$prop.Name])
                }
            }
        }
    }

    foreach ($user in $IdentitySnapshot.Users) {

        $userAssignments = @()
        if ($RbacIndex.ContainsKey($user.UserId)) {
            $userAssignments = $RbacIndex[$user.UserId]
        }

        # Resolve the user's group memberships once per user — needed for the privilege check below.
        $userGroupIds = @()
        if ($IdentitySnapshot.MembershipMap.ContainsKey($user.UserId)) {
            $userGroupIds = $IdentitySnapshot.MembershipMap[$user.UserId]
        }

        # Determine whether this user is privileged using both the snapshot flag and the
        # entitlement model flag. The snapshot flag alone is insufficient because it only
        # reflects tier-based privilege, not the explicit privileged:true on Base-tier groups.
        $isPrivilegedUser = ($user.PSObject.Properties['IsPrivileged'] -and $user.IsPrivileged) -or
            ($userGroupIds | Where-Object { $entitlementPrivGroupIds.Contains($_) }).Count -gt 0


        # CORR-001
        # Privileged identity holding a high-risk RBAC role at subscription scope.
        # Both conditions must be true at once — this is the cross-plane exposure that
        # neither the identity processor nor the RBAC processor can detect independently.
        if ($p.PSObject.Properties['requirePrivilegedTier'] -and $p.requirePrivilegedTier `
            -and $p.PSObject.Properties['forbiddenRoles'] -and $p.PSObject.Properties['forbiddenScopes']) {

            if (-not $isPrivilegedUser) { continue }

            $dangerousAssignments = $userAssignments | Where-Object {
                $a = $_
                ($p.forbiddenRoles -contains $a.RoleDefinitionName) -and
                ($a.ScopeType -eq 'Subscription') -and
                ($p.forbiddenScopes | Where-Object { $a.Scope -like "$_*" })
            }

            foreach ($da in $dangerousAssignments) {
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "Privileged identity holds '$($da.RoleDefinitionName)' at subscription scope '$($da.Scope)' (Sub: $($da.SubscriptionId))."))
            }

            continue
        }


        # CORR-002
        # Disabled account with active RBAC assignments.
        # A disabled account should have no remaining Azure permissions — any RBAC left
        # behind after disabling is residual access that needs to be cleaned up.
        if ($p.PSObject.Properties['requireEnabled'] -and $p.requireEnabled `
            -and $p.PSObject.Properties['requireActiveRbac'] -and $p.requireActiveRbac) {

            if (-not $user.AccountEnabled -and $userAssignments.Count -gt 0) {
                $roleList = ($userAssignments |
                    Select-Object -ExpandProperty RoleDefinitionName -Unique) -join ', '
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "Disabled account still has $($userAssignments.Count) RBAC assignment(s): $roleList."))
            }

            continue
        }


        # CORR-003
        # Non-FTE holding a privileged RBAC role.
        # Contractors and interns should not hold Owner, Contributor, or UAA — these are
        # permanent employee roles. This fires regardless of group membership.
        if ($p.PSObject.Properties['restrictedEmploymentTypes'] -and $p.PSObject.Properties['privilegedRoles']) {

            $rawType  = ($user.EmployeeType ?? '').Trim()
            $normType = switch -Regex ($rawType.ToLower()) {
                '^full.?time$' { 'Full-time'  }
                '^intern$'     { 'Intern'     }
                '^contractor$' { 'Contractor' }
                default        { $rawType }
            }

            if ([string]::IsNullOrWhiteSpace($normType)) { continue }

            $isRestricted = $p.restrictedEmploymentTypes -contains $normType
            if (-not $isRestricted) { continue }

            $privAssignments = $userAssignments |
                Where-Object { $p.privilegedRoles -contains $_.RoleDefinitionName }

            foreach ($pa in $privAssignments) {
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "Non-FTE '$normType' holds privileged role '$($pa.RoleDefinitionName)' at '$($pa.Scope)'."))
            }

            continue
        }


        # CORR-004
        # Privileged identity with a direct (non-group-based) RBAC assignment.
        # All RBAC should be group-based. A privileged identity with direct assignment
        # bypasses group governance and is harder to audit. Suppressed by CORR-001
        # when the higher-severity cross-plane rule already fires for the same entity.
        if ($p.PSObject.Properties['requirePrivilegedTier'] -and $p.requirePrivilegedTier `
            -and $p.PSObject.Properties['assignmentType']) {

            if (-not $isPrivilegedUser) { continue }

            $targetAssignmentType = if ($p.assignmentType -eq 'User') { 'Direct' } else { $p.assignmentType }

            $directAssignments = $userAssignments |
                Where-Object { $_.AssignmentType -eq $targetAssignmentType }

            foreach ($da in $directAssignments) {
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "Privileged identity has direct RBAC assignment '$($da.RoleDefinitionName)' at '$($da.Scope)'."))
            }

            continue
        }


        # CORR-005
        # Dormant account that still holds RBAC roles.
        # Inactive accounts with permissions are a standing lateral movement opportunity —
        # they won't trigger sign-in risk alerts because they never sign in.
        if ($p.PSObject.Properties['maxInactiveDays'] -and $p.PSObject.Properties['requireActiveRbac'] -and $p.requireActiveRbac) {

            if ($userAssignments.Count -eq 0) { continue }

            $lastSignIn = $user.LastSignInDateTime
            $isStale    = $false

            if ($null -eq $lastSignIn) {
                $isStale = $true
            }
            else {
                $daysSince = ($now - [datetime]$lastSignIn).Days
                $isStale   = $daysSince -ge $p.maxInactiveDays
            }

            if ($isStale) {
                $roleList = ($userAssignments |
                    Select-Object -ExpandProperty RoleDefinitionName -Unique) -join ', '

                $inactiveDesc = if ($null -eq $lastSignIn) {
                    'Never signed in'
                }
                else {
                    "$daysSince days inactive"
                }

                $findings.Add((New-ComplianceFinding `
                    -EntityId   $user.UserId `
                    -EntityType 'User' `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "$inactiveDesc but still has $($userAssignments.Count) RBAC assignment(s): $roleList"))
            }

            continue
        }
    }

    return $findings
}


# Dispatch table — RulesDocument ($doc) is now forwarded to Evaluate-CrossPlaneExposure
# so CORR-001 and CORR-004 can read the privileged flag from the entitlement model.
$Script:CorrelationDispatch = @{
    'Evaluate-CrossPlaneExposure' = {
        param($r, $identSnap, $rbacSnap, $rbacIndex, $doc)
        Evaluate-CrossPlaneExposure `
            -Rule             $r `
            -IdentitySnapshot $identSnap `
            -RbacSnapshot     $rbacSnap `
            -RbacIndex        $rbacIndex `
            -RulesDocument    $doc
    }
}


function Invoke-CorrelationRuleEngine {

    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]

    param(
        [Parameter(Mandatory)] [PSCustomObject] $RulesDocument,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot,
        [Parameter(Mandatory)] [PSCustomObject] $RbacSnapshot
    )

    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $rbacIndex = Build-CorrelationRbacIndex -RbacSnapshot $RbacSnapshot

    $rules = $RulesDocument.rules |
        Where-Object { $Script:CorrelationCategories -contains $_.category }

    foreach ($rule in $rules) {

        if (-not $Script:CorrelationDispatch.ContainsKey($rule.type)) {
            Write-Debug "Invoke-CorrelationRuleEngine: No handler for type '$($rule.type)'"
            continue
        }

        try {
            $results = & $Script:CorrelationDispatch[$rule.type] `
                $rule $IdentitySnapshot $RbacSnapshot $rbacIndex $RulesDocument

            if ($results) {
                foreach ($f in $results) { $allFindings.Add($f) }
            }
        }
        catch {
            Write-Debug "Invoke-CorrelationRuleEngine: Rule '$($rule.id)' threw: $_"
        }
    }

# Guard: only run suppression pass if there are findings.
# An empty List[PSCustomObject] unwraps to $null under Set-StrictMode
# which causes SuppressionPass to reject the Findings parameter.
if ($allFindings.Count -gt 0) {
    $allFindings = Invoke-SuppressionPass `
        -Findings      $allFindings `
        -RulesDocument $RulesDocument
}
return ,$allFindings
}