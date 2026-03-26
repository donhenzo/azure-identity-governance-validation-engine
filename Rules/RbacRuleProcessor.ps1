<#
.SYNOPSIS
    RbacRuleProcessor.ps1 — Evaluates RBAC rules from Rules.json against the RBAC snapshot.

.DESCRIPTION
    Processes rules in the RBAC category only.
    Operates exclusively on the RbacSnapshot produced by RbacCollector.ps1.
    Does NOT use Microsoft Graph identity-plane data.

    Scope-aware: rules can differentiate risk by ScopeType:
        Subscription | ResourceGroup | Resource | ManagementGroup

    Returns a flat list of ComplianceFinding objects.
    No aggregation, scoring, or reporting logic here.

.NOTES
    FindingSchema.ps1 must be dot-sourced before execution.
#>

Set-StrictMode -Version Latest

$Script:RbacCategories = @('RBAC')


# Resolve-RbacEntityType
# Maps RBAC PrincipalType values to ComplianceFinding EntityType schema values.
# Managed Identities appear as ServicePrincipal in the RBAC API.
function Resolve-RbacEntityType {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $PrincipalType
    )

    switch ($PrincipalType) {
        'User'             { return 'User'             }
        'Group'            { return 'Group'            }
        'ServicePrincipal' { return 'ServicePrincipal' }
        'MSI'              { return 'ServicePrincipal' }  # Managed Identity
        default            { return 'User'             }  # Unknown principal types default to User to avoid silent drops
    }
}

# ---------------------------------------------------------------------------
# Evaluate-RbacAssignments
# Checks RBAC assignments for three things:
#   1. Users assigned roles directly instead of via groups (RBAC-001)
#   2. Privileged roles assigned at a broad forbidden scope (RBAC-002)
#   3. Forbidden roles assigned to any principal type (RBAC-003)
# Resolves EntityType dynamically per assignment.
# ---------------------------------------------------------------------------

function Evaluate-RbacAssignments {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Rule,
        [Parameter(Mandatory)] [PSCustomObject] $RbacSnapshot
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $p        = $Rule.parameters

    foreach ($assignment in $RbacSnapshot.RoleAssignments) {

        $entityType   = Resolve-RbacEntityType -PrincipalType $assignment.PrincipalType
        $isDirectUser = $assignment.PrincipalType -eq 'User'

        # -------------------------------------------------------------------
        # RBAC-001: Direct role assignment to users (roles must be group-based)
        # -------------------------------------------------------------------
        if ($p.PSObject.Properties['allowedAssignmentTypes']) {
            if ($isDirectUser -and $p.allowedAssignmentTypes -notcontains $assignment.AssignmentType) {
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $assignment.PrincipalId `
                    -EntityType $entityType `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "Direct role assignment: '$($assignment.RoleDefinitionName)' at '$($assignment.Scope)' ($($assignment.ScopeType)). Roles must be group-based."))
            }
            continue
        }

        # -------------------------------------------------------------------
        # RBAC-002: Privileged role at a forbidden broad scope
        # Applies to User, Group, and ServicePrincipal
        # -------------------------------------------------------------------
        if ($p.PSObject.Properties['forbiddenScopes'] -and $p.PSObject.Properties['privilegedRoles']) {
            $isPrivRole = $p.privilegedRoles -contains $assignment.RoleDefinitionName
            # ScopeType was normalized by the collector to: Subscription | ResourceGroup | Resource | ManagementGroup.
            # Using ScopeType directly is more reliable than string pattern matching on Scope path —
            # the pattern "/subscriptions/*" would match ResourceGroup and Resource paths too.
            # forbiddenScopes in Rules.json signals intent (subscription-level is too broad);
            # the ScopeType field is the authoritative classification of that intent.
            $isBroadScope = $assignment.ScopeType -eq 'Subscription'

            if ($isPrivRole -and $isBroadScope) {
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $assignment.PrincipalId `
                    -EntityType $entityType `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "[$($assignment.PrincipalType)] Privileged role '$($assignment.RoleDefinitionName)' at broad scope '$($assignment.Scope)' (Type: $($assignment.ScopeType)). Must be resource-group level or below."))
            }
            continue
        }

        # -------------------------------------------------------------------
        # RBAC-003: Forbidden roles regardless of principal type
        # Flags Owner and User Access Administrator without PIM
        # -------------------------------------------------------------------
        if ($p.PSObject.Properties['forbiddenRoles']) {
            if ($p.forbiddenRoles -contains $assignment.RoleDefinitionName) {
                $findings.Add((New-ComplianceFinding `
                    -EntityId   $assignment.PrincipalId `
                    -EntityType $entityType `
                    -RuleId     $Rule.id `
                    -Category   $Rule.category `
                    -Severity   $Rule.severity `
                    -Weight     $Rule.weight `
                    -Blocking   $Rule.blocking `
                    -Details    "[$($assignment.PrincipalType)] Forbidden role '$($assignment.RoleDefinitionName)' at '$($assignment.Scope)' (Type: $($assignment.ScopeType), Sub: $($assignment.SubscriptionId))."))
            }
            continue
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Dispatch table
# Maps rule.type in Rules.json to evaluation functions.
# Allows additional rule engines to be added without changing orchestration logic.
# ---------------------------------------------------------------------------

$Script:RbacDispatch = @{
    'Evaluate-DirectRoleAssignments' = { param($r, $snap, $doc) Evaluate-RbacAssignments -Rule $r -RbacSnapshot $snap }
}

# ---------------------------------------------------------------------------
# Invoke-RbacRuleEngine
# Processes every RBAC rule in Rules.json and returns all findings.
# ---------------------------------------------------------------------------

function Invoke-RbacRuleEngine {
    <#
    .SYNOPSIS
        Evaluates all RBAC rules against the RBAC snapshot.

    .PARAMETER RulesDocument
        Parsed Rules.json object.

    .PARAMETER RbacSnapshot
        Output from Get-RbacSnapshot.

    .OUTPUTS
        List[PSCustomObject] — all RBAC compliance findings
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $RulesDocument,
        [Parameter(Mandatory)] [PSCustomObject] $RbacSnapshot
    )

    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $rules = $RulesDocument.rules | Where-Object { $Script:RbacCategories -contains $_.category }

    foreach ($rule in $rules) {

        if (-not $Script:RbacDispatch.ContainsKey($rule.type)) {
            Write-Debug "Invoke-RbacRuleEngine: No handler for type '$($rule.type)' (rule: $($rule.id))"
            continue
        }

        try {
            $results = & $Script:RbacDispatch[$rule.type] $rule $RbacSnapshot $RulesDocument
            if ($results) {
                foreach ($f in $results) { $allFindings.Add($f) }
            }
        }
        catch {
            # Skip a failing rule without crashing the whole scan
            Write-Debug "Invoke-RbacRuleEngine: Rule '$($rule.id)' threw: $_"
        }
    }

    # ── Suppression pass — RBAC-002 suppressed by RBAC-003 per entity+scope ──
    # RBAC-003 (forbidden role) is more specific than RBAC-002 (broad scope warning).
    # When RBAC-003 fires for entity E at scope S, RBAC-002 for the same E+S+role
    # is redundant — the forbidden-role finding already captures the violation fully.
    # Suppression is scope-aware: RBAC-002 on a *different* scope still emits.

    $suppressionRules = @($RulesDocument.rules | Where-Object {
        $_.PSObject.Properties['suppressesOnMatch'] -and $_.suppressesOnMatch.Count -gt 0
    })

    if ($suppressionRules.Count -gt 0) {
        # Build suppression key set: "entityId::scope::role" where RBAC-003 fired
        # Keys extracted from the Details field: role name and scope are both present
        $suppressKeys = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)

        foreach ($sr in $suppressionRules) {
            $firedFindings = @($allFindings | Where-Object { $_.RuleId -eq $sr.id })
            foreach ($ff in $firedFindings) {
                # Extract scope from Details: "...at '<scope>'..."
                $scopeMatch = [regex]::Match($ff.Details, "at '([^']+)'")
                $scope = if ($scopeMatch.Success) { $scopeMatch.Groups[1].Value } else { '__any__' }
                # Extract role from Details: "role '<role>' at..."
                $roleMatch  = [regex]::Match($ff.Details, "role '([^']+)'")
                $role = if ($roleMatch.Success) { $roleMatch.Groups[1].Value } else { '__any__' }

                foreach ($ruleToSuppress in $sr.suppressesOnMatch) {
                    [void]$suppressKeys.Add("$($ff.EntityId)::$scope::$role::$ruleToSuppress")
                }
            }
        }

        if ($suppressKeys.Count -gt 0) {
            $filtered = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($f in $allFindings) {
                $scopeMatch = [regex]::Match($f.Details, "at '([^']+)'")
                $scope = if ($scopeMatch.Success) { $scopeMatch.Groups[1].Value } else { '__any__' }
                $roleMatch  = [regex]::Match($f.Details, "role '([^']+)'")
                $role = if ($roleMatch.Success) { $roleMatch.Groups[1].Value } else { '__any__' }
                $key = "$($f.EntityId)::$scope::$role::$($f.RuleId)"

                if ($suppressKeys.Contains($key)) {
                    Write-Debug "Invoke-RbacRuleEngine: Suppressed $($f.RuleId) for $($f.EntityId) at scope $scope (superseded by higher-priority rule)"
                } else {
                    $filtered.Add($f)
                }
            }
            $allFindings = $filtered
        }
    }


    # ── Shared suppression pass ───────────────────────────────────────────────
    # Catches any remaining suppressesOnMatch relationships not handled by the
    # scope-aware RBAC-specific pass above.
    $allFindings = Invoke-SuppressionPass -Findings $allFindings -RulesDocument $RulesDocument

    return ,$allFindings
}