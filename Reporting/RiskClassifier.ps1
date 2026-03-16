<#
.SYNOPSIS
    RiskClassifier.ps1 — Dual-model classification engine.

.DESCRIPTION
    Implements a clean separation between compliance state and risk exposure:

        ComplianceStatus — drives JML workflow decisions
            Compliant    No findings
            NonCompliant Findings exist, none are blocking
            Blocking     At least one finding has Blocking = true

        RiskLevel — informational exposure level for security triage
            None         No findings
            Medium       Non-blocking, non-critical severity findings
            High         Non-blocking findings with Critical severity
            Critical     Any blocking finding exists

        RiskScoreRaw — analytics metadata only
            Accumulated weight total. Never used to determine
            ComplianceStatus or RiskLevel. Dashboard/sorting use only.

        RecommendedAction — workflow signal
            None      Compliant
            Alert     NonCompliant, no critical severity
            Review    NonCompliant with critical severity
            Escalate  Blocking findings

    PreProvision: ignores severity and score. Fails only on Blocking findings.
    FullScan:     all rules, full metrics, all entities.
    DriftOnly:    Architecture/RBAC/Access/Correlation only, no Hygiene/Identity.

    This file contains NO Azure calls and NO rule logic.
    It only classifies findings already produced by processors.
#>

Set-StrictMode -Version Latest

# Categories included when running DriftOnly mode
$Script:DriftOnlyCategories = @('Architecture', 'RBAC', 'Access', 'Correlation')


# Get-EntityRiskAggregate
# Classifies ONE entity from its findings using the dual model.

function Get-EntityRiskAggregate {
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string]                                          $EntityId,
        [Parameter(Mandatory)] [string]                                          $EntityType,
        [Parameter()]          [System.Collections.Generic.List[PSCustomObject]] $EntityFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    )

    # Separate compliance findings from hygiene findings 
    # Non-blocking HYG-* findings (inactivity, stale passwords) are operational
    # health signals. They contribute to the risk score but do NOT gate
    # ComplianceStatus — an inactive account is not a compliance failure.
    # Exception: blocking HYG findings (HYG-004: no MFA on privileged account)
    # remain in the compliance gate because MFA is a hard security control.
    $complianceFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $hygieneFindings    = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($f in $EntityFindings) {
        if ($f.RuleId -like 'HYG-*' -and -not $f.Blocking) {
            $hygieneFindings.Add($f)
        } else {
            $complianceFindings.Add($f)
        }
    }

    # Accumulate signals from compliance findings
    $riskScoreRaw   = 0
    $hasBlocking    = $false
    $hasCriticalSev = $false
    $violationCount = $complianceFindings.Count

    foreach ($f in $complianceFindings) {
        $riskScoreRaw += $f.Weight
        if ($f.Blocking -eq $true)      { $hasBlocking    = $true }
        if ($f.Severity -eq 'Critical') { $hasCriticalSev = $true }
    }

    # Hygiene score added to raw total (informational — not compliance gated)
    foreach ($f in $hygieneFindings) { $riskScoreRaw += $f.Weight }

    # Normalise score to 0–100 
    # Fixed theoretical maximum: worst-case single entity stacking all critical rules.
    # Using a fixed constant keeps scores comparable across tenants and over time.
    # Tenant-relative normalisation (score/tenant-max) would compress clean tenants.
    $theoreticalMax = 900
    $riskScore = [Math]::Min([Math]::Round(($riskScoreRaw / $theoreticalMax) * 100, 1), 100.0)

    # Risk density 
    # Distinguishes few severe violations from many minor ones.
    # High density = concentrated critical risk. Low density = broad surface area.
    $totalViolations = $EntityFindings.Count
    $riskDensity = if ($totalViolations -gt 0) {
        [Math]::Round($riskScore / $totalViolations, 2)
    } else { 0.0 }

    # ComplianceStatus — gated on compliance findings only
    $complianceStatus = if ($violationCount -eq 0) {
        'Compliant'
    } elseif ($hasBlocking) {
        'Blocking'
    } else {
        'NonCompliant'
    }

    # RiskLevel — informational, uses full finding set
    $anyBlocking    = $EntityFindings | Where-Object { $_.Blocking }
    $anyCriticalSev = $EntityFindings | Where-Object { $_.Severity -eq 'Critical' }

    $riskLevel = if ($EntityFindings.Count -eq 0) {
        'None'
    } elseif ($anyBlocking) {
        'Critical'
    } elseif ($anyCriticalSev) {
        'High'
    } elseif ($hygieneFindings.Count -gt 0 -and $complianceFindings.Count -eq 0) {
        'Low'       # hygiene-only: operationally notable, not a compliance risk
    } else {
        'Medium'
    }

    # RecommendedAction 
    $recommendedAction = switch ($complianceStatus) {
        'Compliant'    { if ($hygieneFindings.Count -gt 0) { 'HygieneReview' } else { 'None' } }
        'Blocking'     { 'Escalate' }
        'NonCompliant' { if ($hasCriticalSev) { 'Review' } else { 'Alert' } }
    }

    # Invariant guard
    if ($complianceStatus -eq 'Compliant' -and $violationCount -gt 0) {
        throw "ClassifierInvariantViolation: EntityId='$EntityId' ComplianceStatus=Compliant but ViolationCount=$violationCount."
    }

    return [PSCustomObject]@{
        EntityId            = $EntityId
        EntityType          = $EntityType
        ComplianceStatus    = $complianceStatus
        RiskLevel           = $riskLevel
        RiskScore           = $riskScore           # normalised 0-100
        RiskScoreRaw        = $riskScoreRaw        # raw weight sum (analytics use)
        RiskDensity         = $riskDensity         # score / violation count
        ViolationCount      = $violationCount      # compliance findings only
        HygieneIssueCount   = $hygieneFindings.Count
        HasBlocking         = $hasBlocking
        HasCriticalSeverity = $hasCriticalSev
        RecommendedAction   = $recommendedAction
        Findings            = $EntityFindings
    }
}


# Group-FindingsByEntity
# Builds per-entity lookup tables from the flat findings list.
function Group-FindingsByEntity {
    [OutputType([hashtable])]
    param([System.Collections.Generic.List[PSCustomObject]] $Findings)

    $byEntity    = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    $entityTypes = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($f in $Findings) {
        if (-not $byEntity.ContainsKey($f.EntityId)) {
            $byEntity[$f.EntityId]    = [System.Collections.Generic.List[PSCustomObject]]::new()
            $entityTypes[$f.EntityId] = $f.EntityType
        }
        $byEntity[$f.EntityId].Add($f)
    }

    return @{ ByEntity = $byEntity; EntityTypes = $entityTypes }
}


# Invoke-PreProvisionClassification
# Single-entity gate check. Only blocking findings matter.
# Severity and RiskScore are intentionally ignored here.

function Invoke-PreProvisionClassification {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string]                                          $TargetEntityId,
        [Parameter()]          [System.Collections.Generic.List[PSCustomObject]] $Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    )

    $blockingFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($f in $Findings) {
        if ($f.EntityId -eq $TargetEntityId -and $f.Blocking -eq $true) {
            $blockingFindings.Add($f)
        }
    }

    $decision = if ($blockingFindings.Count -eq 0) { 'Pass' } else { 'Fail' }

    return [PSCustomObject]@{
        EntityId      = $TargetEntityId
        EntityType    = 'User'
        Decision      = $decision
        BlockingCount = $blockingFindings.Count
        Reasons       = @($blockingFindings | Select-Object -ExpandProperty Details)
        Findings      = $blockingFindings
        Mode          = 'PreProvision'
        EvaluatedAt   = [datetime]::UtcNow.ToString('o')
    }
}


# Invoke-FullScanClassification
# Scores ALL entities. Returns dual-model state + summary metrics.
function Invoke-FullScanClassification {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]          [System.Collections.Generic.List[PSCustomObject]] $Findings = [System.Collections.Generic.List[PSCustomObject]]::new(),
        [Parameter(Mandatory)] [string[]]                                         $AllEntityIds,
        # Privileged user count — calculated in ValidationEngine.ps1 where the
        # identity snapshot is still in scope. Passed as a scalar to keep the
        # classifier decoupled from the snapshot layer.
        [Parameter()]   [int]   $PrivilegedCount = 0
    )

    $grouped          = Group-FindingsByEntity -Findings $Findings
    $entityRiskStates = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($eid in $AllEntityIds) {

        $entityFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
        if ($grouped.ByEntity.ContainsKey($eid)) {
            $entityFindings = $grouped.ByEntity[$eid]
        }

        $entityType = if ($grouped.EntityTypes.ContainsKey($eid)) {
            $grouped.EntityTypes[$eid]
        } else {
            'User'
        }

        $aggregate = Get-EntityRiskAggregate -EntityId $eid -EntityType $entityType -EntityFindings $entityFindings
        $entityRiskStates.Add($aggregate)
    }

    # Summary metrics — compliance-driven, not score-driven 
    $totalCount      = $entityRiskStates.Count
    $compliantCount  = @($entityRiskStates | Where-Object { $_.ComplianceStatus -eq 'Compliant'    }).Count
    $nonCompliant    = @($entityRiskStates | Where-Object { $_.ComplianceStatus -eq 'NonCompliant' }).Count
    $blockingCount   = @($entityRiskStates | Where-Object { $_.ComplianceStatus -eq 'Blocking'     }).Count

    $pctCompliant  = if ($totalCount -gt 0) { [Math]::Round(($compliantCount  / $totalCount) * 100, 1) } else { 0 }
    $pctPrivileged = if ($totalCount -gt 0) { [Math]::Round(($PrivilegedCount / $totalCount) * 100, 1) } else { 0 }

    $summary = [PSCustomObject]@{
        TotalIdentities             = $totalCount
        TotalCompliant              = $compliantCount
        TotalNonCompliant           = $nonCompliant
        TotalBlocking               = $blockingCount
        PercentCompliant            = $pctCompliant
        TotalPrivileged             = $PrivilegedCount
        PercentPrivileged           = $pctPrivileged
        TotalArchitectureViolations = @($Findings | Where-Object { $_.Category -eq 'Architecture' }).Count
        TotalDirectRBACAssignments  = @($Findings | Where-Object { $_.Category -eq 'RBAC'         }).Count
        TotalCorrelationFindings    = @($Findings | Where-Object { $_.Category -eq 'Correlation'   }).Count
        TotalAccessViolations       = @($Findings | Where-Object { $_.Category -eq 'Access'        }).Count
    }

    return [PSCustomObject]@{
        EntityRiskStates = $entityRiskStates
        Summary          = $summary
        Mode             = 'FullScan'
        ClassifiedAt     = [datetime]::UtcNow.ToString('o')
    }
}


# Invoke-DriftOnlyClassification
# Structural drift categories only — no Identity or Hygiene findings.

function Invoke-DriftOnlyClassification {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]          [System.Collections.Generic.List[PSCustomObject]] $Findings = [System.Collections.Generic.List[PSCustomObject]]::new(),
        [Parameter(Mandatory)] [string[]]                                         $AllEntityIds
    )

    $driftFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($f in $Findings) {
        if ($Script:DriftOnlyCategories -contains $f.Category) {
            $driftFindings.Add($f)
        }
    }

    $grouped          = Group-FindingsByEntity -Findings $driftFindings
    $entityRiskStates = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($eid in $AllEntityIds) {
        if (-not $grouped.ByEntity.ContainsKey($eid)) { continue }

        $aggregate = Get-EntityRiskAggregate `
            -EntityId       $eid `
            -EntityType     $grouped.EntityTypes[$eid] `
            -EntityFindings $grouped.ByEntity[$eid]

        $entityRiskStates.Add($aggregate)
    }

    $summary = [PSCustomObject]@{
        TotalEntitiesWithDrift      = $entityRiskStates.Count
        TotalBlocking               = @($entityRiskStates | Where-Object { $_.ComplianceStatus -eq 'Blocking'     }).Count
        TotalNonCompliant           = @($entityRiskStates | Where-Object { $_.ComplianceStatus -eq 'NonCompliant' }).Count
        TotalArchitectureViolations = @($driftFindings    | Where-Object { $_.Category -eq 'Architecture' }).Count
        TotalDirectRBACAssignments  = @($driftFindings    | Where-Object { $_.Category -eq 'RBAC'         }).Count
        TotalCorrelationFindings    = @($driftFindings    | Where-Object { $_.Category -eq 'Correlation'   }).Count
        TotalAccessViolations       = @($driftFindings    | Where-Object { $_.Category -eq 'Access'        }).Count
    }

    return [PSCustomObject]@{
        EntityRiskStates = $entityRiskStates
        Summary          = $summary
        Mode             = 'DriftOnly'
        ClassifiedAt     = [datetime]::UtcNow.ToString('o')
    }
}


# Invoke-RiskClassification — public entry point

function Invoke-RiskClassification {

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PreProvision', 'FullScan', 'DriftOnly')]
        [string] $Mode,

        [Parameter()]
        [System.Collections.Generic.List[PSCustomObject]] $Findings = [System.Collections.Generic.List[PSCustomObject]]::new(),

        [Parameter()] [string[]] $AllEntityIds    = @(),
        [Parameter()] [string]   $TargetEntityId  = '',
        [Parameter()] [int]      $PrivilegedCount  = 0
    )

    switch ($Mode) {

        'PreProvision' {
            if ([string]::IsNullOrWhiteSpace($TargetEntityId)) {
                throw 'TargetEntityId is required for PreProvision mode.'
            }
            return Invoke-PreProvisionClassification -TargetEntityId $TargetEntityId -Findings $Findings
        }

        'FullScan' {
            if ($AllEntityIds.Count -eq 0) {
                throw 'AllEntityIds must be provided for FullScan mode.'
            }
            return Invoke-FullScanClassification -Findings $Findings -AllEntityIds $AllEntityIds -PrivilegedCount $PrivilegedCount
        }

        'DriftOnly' {
            if ($AllEntityIds.Count -eq 0) {
                throw 'AllEntityIds must be provided for DriftOnly mode.'
            }
            return Invoke-DriftOnlyClassification -Findings $Findings -AllEntityIds $AllEntityIds
        }
    }
}