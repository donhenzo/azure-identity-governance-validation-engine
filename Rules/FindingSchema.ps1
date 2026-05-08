<#
.SYNOPSIS
    FindingSchema.ps1 — Defines the single finding object shape used across all processors.

.DESCRIPTION
    This file defines the canonical schema for every compliance finding.
    All rule processors must use this constructor to emit findings.
    No processor should manually build findings — this enforces consistency.

    Finding shape:
        EntityId   | EntityType | RuleId   | Category | Severity
        Weight     | Blocking   | Details  | Timestamp | Mode

    EntityType values: User | Group | ServicePrincipal | App | Subscription | Device | Policy
    Current implementation emits EntityType = 'User', but schema is future-proofed.
#>

Set-StrictMode -Version Latest

function New-ComplianceFinding {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(

        # The ID of the entity being evaluated (e.g., UserId, GroupId, AppId)
        [Parameter(Mandatory)] [string] $EntityId,

        # What type of object this finding applies to
        [Parameter(Mandatory)]
        [ValidateSet('User', 'Group', 'ServicePrincipal', 'App', 'Subscription', 'Device', 'Policy')]
        [string] $EntityType,

        # Unique rule identifier (e.g., IDENT-001, ENT-003)
        [Parameter(Mandatory)] [string] $RuleId,

        # High-level classification (Identity | Access | Architecture | Hygiene | RBAC | Correlation)
        [Parameter(Mandatory)] [string] $Category,

        # Severity label — drives risk classification and report colouring
        [Parameter(Mandatory)]
        [ValidateSet('Low', 'Medium', 'High', 'Critical')]
        [string] $Severity,

        # Numeric risk contribution — bounded to prevent scoring manipulation
        [Parameter(Mandatory)]
        [ValidateRange(0, 100)]
        [int] $Weight,

        # True = triggers auto-remediation or hard block in PreProvision mode
        [Parameter(Mandatory)] [bool] $Blocking,

        # Human-readable explanation surfaced in reports and dashboards
        [Parameter(Mandatory)] [string] $Details,

        # Scan mode that produced this finding
        [Parameter()]
        [ValidateSet('FullScan', 'DeltaScan', 'Simulation', 'TargetedScan')]
        [string] $Mode = 'FullScan'
    )

    return [PSCustomObject]@{
        EntityId   = $EntityId
        EntityType = $EntityType
        RuleId     = $RuleId
        Category   = $Category
        Severity   = $Severity
        Weight     = $Weight
        Blocking   = $Blocking
        Details    = $Details
        Timestamp  = [datetime]::UtcNow.ToString('o')   # ISO 8601 for SIEM ingestion
        Mode       = $Mode
    }
}


# Invoke-SuppressionPass
# Post-processing step called by every rule orchestrator after all rules run.
# Reads suppressesOnMatch from Rules.json and removes findings for rules that
# are superseded by a higher-priority rule firing on the same entity.
#
# Suppression is entity-scoped (same EntityId). For scope-aware suppression
# (RBAC-002 vs RBAC-003 per subscription), the RBAC orchestrator handles it
# separately using scope keys — this handles all other cases.
#
# Contract:
#   suppressesOnMatch: ["HYG-001"] on HYG-002 means:
#     for every EntityId where HYG-002 fired, remove all HYG-001 findings.


function Invoke-SuppressionPass {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [System.Collections.Generic.List[PSCustomObject]] $Findings,
        [Parameter(Mandatory)] [PSCustomObject]                                   $RulesDocument
    )

    # Find rules that suppress others — guard against null/missing property
    $suppressionRules = @($RulesDocument.rules | Where-Object {
        $_.PSObject.Properties['suppressesOnMatch'] -and
        $null -ne $_.suppressesOnMatch -and
        @($_.suppressesOnMatch).Count -gt 0
    })

    if ($suppressionRules.Count -eq 0) { return $Findings }

    # Build: entityId -> HashSet of ruleIds to suppress
    $suppressMap = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($sr in $suppressionRules) {
        $firedEntities = @($Findings |
            Where-Object { $_.RuleId -eq $sr.id } |
            Select-Object -ExpandProperty EntityId -Unique)

        foreach ($eid in $firedEntities) {
            if (-not $suppressMap.ContainsKey($eid)) {
                $suppressMap[$eid] = [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::OrdinalIgnoreCase)
            }
            foreach ($ruleToSuppress in @($sr.suppressesOnMatch)) {
                [void]$suppressMap[$eid].Add($ruleToSuppress)
            }
        }
    }

    if ($suppressMap.Count -eq 0) { return $Findings }

    $filtered = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($f in $Findings) {
        if ($suppressMap.ContainsKey($f.EntityId) -and
            $suppressMap[$f.EntityId].Contains($f.RuleId)) {
            Write-Debug "SuppressionPass: removed $($f.RuleId) for $($f.EntityId) (superseded)"
        } else {
            $filtered.Add($f)
        }
    }

    return $filtered
}