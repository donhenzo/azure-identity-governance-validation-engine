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

# ---------------------------------------------------------------------------
# Correlation Engine Architecture
#
# Evaluates identity + RBAC relationships that cannot be detected from
# either dataset independently.
#
# Pipeline:
#   1. Build RBAC lookup index (PrincipalId → assignments)
#   2. Iterate identities
#   3. Evaluate rule conditions using RBAC + identity context
#   4. Emit ComplianceFinding objects
# ---------------------------------------------------------------------------

$Script:CorrelationCategories = @('Correlation')

# ---------------------------------------------------------------------------
# Build RBAC lookup index: PrincipalId → list of assignments.
# Avoids repeatedly scanning the RBAC dataset for each identity.
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Core correlation evaluator.
# Rule behaviour is driven entirely by parameters in Rules.json.
# ---------------------------------------------------------------------------

function Evaluate-CrossPlaneExposure {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Rule,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot,
        [Parameter(Mandatory)] [PSCustomObject] $RbacSnapshot,
        [Parameter(Mandatory)] [hashtable]      $RbacIndex
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $p        = $Rule.parameters
    $now      = [datetime]::UtcNow

    foreach ($user in $IdentitySnapshot.Users) {

        # Lookup RBAC assignments for this identity
        $userAssignments = @()
        if ($RbacIndex.ContainsKey($user.UserId)) {
            $userAssignments = $RbacIndex[$user.UserId]
        }

        # ================================================================
        # CORR-001
        # Privileged identity holding high-risk subscription RBAC roles
        # ================================================================
        if ($p.PSObject.Properties['requirePrivilegedTier'] -and $p.requirePrivilegedTier `
            -and $p.PSObject.Properties['forbiddenRoles'] -and $p.PSObject.Properties['forbiddenScopes']) {

            # Guard against schema drift if IsPrivileged flag is missing
            if (-not $user.PSObject.Properties['IsPrivileged']) {
                Write-Debug "CorrelationProcessor: User '$($user.UserId)' missing IsPrivileged flag."
                continue
            }

            if (-not $user.IsPrivileged) { continue }

            # Detect high-risk subscription scope assignments
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

        # ================================================================
        # CORR-002
        # Disabled identity retaining active RBAC permissions
        # ================================================================
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

        # ================================================================
        # CORR-003
        # Non-FTE identities assigned privileged RBAC roles
        # ================================================================
        if ($p.PSObject.Properties['restrictedEmploymentTypes'] -and $p.PSObject.Properties['privilegedRoles']) {

            # Normalise EmployeeType values from HR / directory sync
            $rawType = ($user.EmployeeType ?? '').Trim()

            $normType = switch -Regex ($rawType.ToLower()) {
                '^full.?time$' { 'Full-time'  }
                '^intern$'     { 'Intern'     }
                '^contractor$' { 'Contractor' }
                default        { $rawType }
            }

            # Missing EmployeeType handled by identity rules
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

        # ================================================================
        # CORR-004
        # Privileged identity with direct RBAC assignment
        # ================================================================
        if ($p.PSObject.Properties['requirePrivilegedTier'] -and $p.requirePrivilegedTier `
            -and $p.PSObject.Properties['assignmentType']) {

            if (-not $user.PSObject.Properties['IsPrivileged']) {
                Write-Debug "CorrelationProcessor: User '$($user.UserId)' missing IsPrivileged flag."
                continue
            }

            if (-not $user.IsPrivileged) { continue }

            # Normalise assignment type to collector values
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

        # ================================================================
        # CORR-005
        # Dormant identity retaining RBAC permissions
        # ================================================================
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

# ---------------------------------------------------------------------------
# Rule dispatch table (rule.type → evaluator)
# ---------------------------------------------------------------------------

$Script:CorrelationDispatch = @{
    'Evaluate-CrossPlaneExposure' = {
        param($r, $identSnap, $rbacSnap, $rbacIndex, $doc)

        Evaluate-CrossPlaneExposure `
            -Rule $r `
            -IdentitySnapshot $identSnap `
            -RbacSnapshot $rbacSnap `
            -RbacIndex $rbacIndex
    }
}

# ---------------------------------------------------------------------------
# Engine entry point for correlation rule execution
# ---------------------------------------------------------------------------

function Invoke-CorrelationRuleEngine {

    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]

    param(
        [Parameter(Mandatory)] [PSCustomObject] $RulesDocument,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot,
        [Parameter(Mandatory)] [PSCustomObject] $RbacSnapshot
    )

    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Build RBAC index once for this engine run
    $rbacIndex = Build-CorrelationRbacIndex -RbacSnapshot $RbacSnapshot

    # Select only correlation rules from Rules.json
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

    # -------------------------------------------------------------------
    # Suppression pass removes overlapping findings between rules
    # -------------------------------------------------------------------

    $allFindings = Invoke-SuppressionPass `
        -Findings $allFindings `
        -RulesDocument $RulesDocument

    return $allFindings
}