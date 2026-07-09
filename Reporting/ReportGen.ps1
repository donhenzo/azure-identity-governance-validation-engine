<#
.SYNOPSIS
    ReportGenerator.ps1 — Structured output, governance metrics, and export.

.DESCRIPTION
    Responsibility: Translate classification results from RiskClassifier into
    human-readable governance reports and machine-consumable export files.

    ARCHITECTURAL CONTRACT:
    ✔  Accepts classification output from Invoke-RiskClassification
    ✔  Generates governance metrics (% compliant, % privileged, drift)
    ✔  Exports CSV and/or JSON
    ✔  Compares against previous run for drift trend
    ✔  Writes to console (this is the only layer that may do so)
    ✘  Must NOT evaluate rules
    ✘  Must NOT fetch Azure data
    ✘  Must NOT modify risk scores or findings
    ✘  Must NOT make Pass/Fail decisions

.NOTES
    Engine Layer : 4 — Reporting & Export
    Depends On   : RiskClassifier.ps1 output
#>

Set-StrictMode -Version Latest

#  CONSTANTS
# $PSScriptRoot here resolves to Reporting/ — one level below the engine root.
# DefaultOutputDir is set relative to the engine root so Output/ sits alongside
# ValidationEngine.ps1, not inside Reporting/.
# LastRunStateFile is intentionally NOT set as a module-level constant anymore —
# it is derived from $OutputDir at call time in Write-GovernanceReport and
# Get-GovernanceMetrics so the state file always lands in the same directory
# as the rest of the run's output.

$Script:DefaultOutputDir = Join-Path $PSScriptRoot '..' 'Output'


#  PRIVATE HELPERS

function Ensure-ReportOutputDirectory {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Load-ReportLastRunState {
    [OutputType([PSCustomObject])]
    param([string] $StatePath)

    if (Test-Path -LiteralPath $StatePath) {
        try {
            return Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
        }
        catch {
            Write-Debug "ReportGenerator: Could not load last-run state from '$StatePath': $_"
        }
    }
    return $null
}

function Save-ReportLastRunState {
    param(
        [string]         $StatePath,
        [PSCustomObject] $Summary,
        [string]         $RunTimestamp
    )

    $state = [PSCustomObject]@{
        RunTimestamp      = $RunTimestamp
        TotalIdentities   = $Summary.TotalIdentities
        TotalCompliant    = $Summary.TotalCompliant
        TotalNonCompliant = $Summary.TotalNonCompliant
        TotalBlocking     = $Summary.TotalBlocking
        PercentCompliant  = $Summary.PercentCompliant
        PercentPrivileged = $Summary.PercentPrivileged
        TotalArchitectureViolations = $Summary.TotalArchitectureViolations
        TotalDirectRBACAssignments  = $Summary.TotalDirectRBACAssignments
    }

    try {
        $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8
    }
    catch {
        Write-Debug "ReportGenerator: Could not save run state to '$StatePath': $_"
    }
}

function Calculate-ReportDriftTrend {
    [OutputType([PSCustomObject])]
    param(
        [PSCustomObject] $Current,
        [PSCustomObject] $Previous
    )

    if ($null -eq $Previous) {
        return [PSCustomObject]@{
            Available      = $false
            PreviousRun    = $null
            CompliantDelta = $null
            RiskTrendPct   = $null
            RiskTrendText  = 'No previous run available for comparison.'
        }
    }

    $currentRisk  = $Current.TotalIdentities - $Current.TotalCompliant
    $previousRisk = $Previous.TotalIdentities - $Previous.TotalCompliant

    $delta = if ($previousRisk -gt 0) {
        [Math]::Round((($currentRisk - $previousRisk) / $previousRisk) * 100, 1)
    }
    else { 0 }

    $trendText = if ($delta -gt 0) {
        "Risk trend: +$delta% (deteriorating)"
    }
    elseif ($delta -lt 0) {
        "Risk trend: $delta% (improving)"
    }
    else {
        "Risk trend: 0% (stable)"
    }

    return [PSCustomObject]@{
        Available         = $true
        PreviousRun       = $Previous.RunTimestamp
        PreviousCompliant = $Previous.TotalCompliant
        CurrentCompliant  = $Current.TotalCompliant
        CompliantDelta    = $Current.TotalCompliant - $Previous.TotalCompliant
        RiskTrendPct      = $delta
        RiskTrendText     = $trendText
    }
}

function Format-ReportSeverityBar {
    <# Produces a simple ASCII distribution bar for console output. #>
    param([int]$Blocking, [int]$NonCompliant, [int]$Compliant)
    return "  Blocking: $Blocking  |  NonCompliant: $NonCompliant  |  Compliant: $Compliant"
}


# PreProvision Report — simplified Pass/Fail output for the JML flow.

function Write-PreProvisionReport {
    <#
    .SYNOPSIS
        Writes a concise PreProvision Pass/Fail report to the console.

    .PARAMETER ClassificationResult
        Output from Invoke-RiskClassification -Mode PreProvision.

    .PARAMETER TargetDisplayName
        Optional display name of the target user for readability.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $ClassificationResult,
        [Parameter()]          [string]         $TargetDisplayName = ''
    )

    $nameLabel     = if ($TargetDisplayName) { "'$TargetDisplayName'" } else { $ClassificationResult.EntityId }
    $decisionColor = if ($ClassificationResult.Decision -eq 'Pass') { 'Green' } else { 'Red' }

    Write-Host ''
    Write-Host '══════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host "  PRE-PROVISION EVALUATION — $nameLabel"           -ForegroundColor Cyan
    Write-Host '══════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host "  Decision     : $($ClassificationResult.Decision)" -ForegroundColor $decisionColor
    Write-Host "  Evaluated At : $($ClassificationResult.EvaluatedAt)"
    Write-Host "  Blocking Violations: $($ClassificationResult.BlockingCount)"

    if ($ClassificationResult.BlockingCount -gt 0) {
        Write-Host ''
        Write-Host '  Blocking Reasons:' -ForegroundColor Yellow
        foreach ($reason in $ClassificationResult.Reasons) {
            Write-Host "    • $reason" -ForegroundColor Yellow
        }
    }
    Write-Host '══════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host ''
}


#  FullScan / DriftOnly Report

function Write-GovernanceReport {
    <#
    .SYNOPSIS
        Writes a full governance metrics report to the console and exports
        findings to CSV and JSON.

    .PARAMETER ClassificationResult
        Output from Invoke-RiskClassification -Mode FullScan or DriftOnly.

    .PARAMETER OutputDir
        Directory for exported files and the LastRunState.json drift baseline.
        Defaults to .\Output\ relative to the engine root.
        The state file is always written to this same directory so that CSV,
        JSON, and drift state are co-located and the next run reads from the
        same place it wrote to.

    .PARAMETER ExportCsv
        Switch: export findings to CSV.

    .PARAMETER ExportJson
        Switch: export findings to JSON.

    .PARAMETER StoreDriftState
        Switch: save current run state for drift comparison on next run.

    .PARAMETER ScanMode
        'online' or 'offline'. Recorded in the report header and JSON so the
        reader knows whether the data came from Graph or from a CSV export.

    .PARAMETER RulesEvaluated
        Rule IDs present in the Rules.json used for this run — the exact set of
        rules in scope. In the per-engagement model this is the curated rule set.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $ClassificationResult,
        [Parameter()]          [string]         $OutputDir      = $Script:DefaultOutputDir,
        [Parameter()]          [switch]         $ExportCsv,
        [Parameter()]          [switch]         $ExportJson,
        [Parameter()]          [switch]         $StoreDriftState,
        [Parameter()]          [hashtable]      $EnrichmentMap  = @{},
        [Parameter()]          [string]         $ScanMode       = 'online',
        [Parameter()]          [string[]]       $RulesEvaluated = @()
    )

    Ensure-ReportOutputDirectory -Path $OutputDir

    # Derive the state file path from OutputDir at runtime — NOT from the module-level
    # constant. This ensures LastRunState.json is always co-located with the CSV/JSON
    # exports for this run, and that the next run's Load call reads from the same place.
    $stateFilePath = Join-Path $OutputDir 'LastRunState.json'

    $runTimestamp = [datetime]::UtcNow.ToString('yyyyMMdd_HHmmss')
    $mode         = $ClassificationResult.Mode
    $summary      = $ClassificationResult.Summary
    $userStates   = $ClassificationResult.EntityRiskStates

    # Load Previous State for Drift Comparison (only for FullScan mode)
    $previousState = Load-ReportLastRunState -StatePath $stateFilePath
    $drift         = $null

    if ($mode -eq 'FullScan') {
        $drift = Calculate-ReportDriftTrend -Current $summary -Previous $previousState
    }

    # Console Output
    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host "║        GOVERNANCE VALIDATION REPORT  [$mode]"                 -ForegroundColor Cyan
    Write-Host "║        Run: $runTimestamp UTC"                                 -ForegroundColor Cyan
    Write-Host "║        Source: $ScanMode  |  Rules in scope: $($RulesEvaluated.Count)" -ForegroundColor Cyan
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''

    if ($mode -eq 'FullScan') {

        Write-Host '  IDENTITY OVERVIEW' -ForegroundColor White
        Write-Host "    Total Identities Evaluated : $($summary.TotalIdentities)"
        Write-Host "    Compliant                  : $($summary.TotalCompliant)  ($($summary.PercentCompliant)%)" -ForegroundColor Green
        Write-Host "    Non-Compliant              : $($summary.TotalNonCompliant)"                               -ForegroundColor Yellow
        Write-Host "    Blocking                   : $($summary.TotalBlocking)"                                   -ForegroundColor Red
        Write-Host ''
        Write-Host '  PRIVILEGE & ARCHITECTURE' -ForegroundColor White
        Write-Host "    Privileged Identities      : $($summary.TotalPrivileged)  ($($summary.PercentPrivileged)%)"
        Write-Host "    Architecture Violations    : $($summary.TotalArchitectureViolations)"
        Write-Host "    Direct RBAC Assignments    : $($summary.TotalDirectRBACAssignments)"
        Write-Host ''

        # SoD conflicts — aggregate from all entity findings, category = SoD
        $sodFindings      = @($userStates | ForEach-Object { $_.Findings } | Where-Object { $_.Category -eq 'SoD' })
        $sodBlockingCount = @($sodFindings | Where-Object { $_.Blocking -eq $true  }).Count
        $sodWarnCount     = @($sodFindings | Where-Object { $_.Blocking -eq $false }).Count

        if ($sodFindings.Count -gt 0) {
            Write-Host '  SoD CONFLICTS' -ForegroundColor White
            Write-Host "    Total Conflicts            : $($sodFindings.Count)  ($sodBlockingCount blocking, $sodWarnCount warnings)" -ForegroundColor Yellow
            Write-Host ''
        }

        # Orphaned users and groups — aggregate from HYG-005 and HYG-006 findings
        $orphanedUserCount  = @($userStates | ForEach-Object { $_.Findings } |
            Where-Object { $_.RuleId -eq 'HYG-005' }).Count
        $orphanedGroupCount = @($userStates | ForEach-Object { $_.Findings } |
            Where-Object { $_.RuleId -eq 'HYG-006' }).Count

        if ($orphanedUserCount -gt 0 -or $orphanedGroupCount -gt 0) {
            Write-Host '  ORPHANED OBJECTS' -ForegroundColor White
            Write-Host "    Users with no group memberships : $orphanedUserCount" -ForegroundColor Yellow
            Write-Host "    Groups with no members          : $orphanedGroupCount" -ForegroundColor Yellow
            Write-Host ''
        }

        if ($null -ne $drift -and $drift.Available) {
            Write-Host '  DRIFT ANALYSIS' -ForegroundColor White
            Write-Host "    Previous Run               : $($drift.PreviousRun)"
            Write-Host "    Compliant Delta            : $($drift.CompliantDelta)"
            $trendColor = if ($drift.RiskTrendPct -gt 0) { 'Red' } elseif ($drift.RiskTrendPct -lt 0) { 'Green' } else { 'White' }
            Write-Host "    $($drift.RiskTrendText)" -ForegroundColor $trendColor
            Write-Host ''
        }
        elseif ($null -ne $drift) {
            Write-Host "  DRIFT: $($drift.RiskTrendText)" -ForegroundColor Gray
            Write-Host ''
        }

    }
    elseif ($mode -eq 'DriftOnly') {

        Write-Host '  DRIFT SCAN OVERVIEW' -ForegroundColor White
        Write-Host "    Entities with Drift        : $($summary.TotalEntitiesWithDrift)"
        Write-Host "    Blocking                   : $($summary.TotalBlocking)"          -ForegroundColor Red
        Write-Host "    Non-Compliant              : $($summary.TotalNonCompliant)"      -ForegroundColor Yellow
        Write-Host "    Architecture Violations    : $($summary.TotalArchitectureViolations)"
        Write-Host "    Direct RBAC Assignments    : $($summary.TotalDirectRBACAssignments)"
        Write-Host "    Access Violations          : $($summary.TotalAccessViolations)"
        Write-Host ''
    }

    # Critical/High Users Spotlight — top 10 riskiest for quick attention.
    $spotlightUsers = @($userStates |
        Where-Object { $_.ComplianceStatus -in @('Blocking', 'NonCompliant') } |
        Sort-Object RiskScore -Descending |
        Select-Object -First 10)

    if ($spotlightUsers.Count -gt 0) {
        Write-Host '  TOP RISK ENTITIES (Critical / High Risk)' -ForegroundColor Yellow
        foreach ($u in $spotlightUsers) {
            $color = if ($u.ComplianceStatus -eq 'Blocking') { 'Red' } else { 'DarkYellow' }
            $ctx   = if ($EnrichmentMap.ContainsKey($u.EntityId)) { $EnrichmentMap[$u.EntityId] } else { $null }
            $label = if ($ctx -and $ctx.UPN)         { $ctx.UPN         } else { $u.EntityId  }
            $name  = if ($ctx -and $ctx.DisplayName) { $ctx.DisplayName } else { $u.EntityType }
            $tier  = if ($ctx -and $ctx.Tier)        { $ctx.Tier        } else { 'N/A'         }
            Write-Host ("    [{0,-10}] Score: {1,5}  Density: {2,5}  Violations: {3,3}  Tier: {4,-14}  {5} ({6})" -f `
                $u.ComplianceStatus, $u.RiskScore, $u.RiskDensity, $u.ViolationCount, $tier, $label, $name) -ForegroundColor $color
        }
        Write-Host ''
    }

    Write-Host '══════════════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host ''

    # Export Findings
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($u in $userStates) {
        foreach ($f in $u.Findings) {
            $allFindings.Add($f)
        }
    }

    if ($ExportCsv -and $allFindings.Count -gt 0) {
        $csvPath = Join-Path $OutputDir "$($mode)_Findings_$runTimestamp.csv"
        try {
            $enrichedRows = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($f in $allFindings) {

                $ctx = if ($EnrichmentMap.ContainsKey($f.EntityId)) {
                $EnrichmentMap[$f.EntityId]
            } else {
                [PSCustomObject]@{
                    UPN=''; DisplayName=''; EntityType=$f.EntityType
                    OnPremisesSynced=$false
                    EmployeeType=''; EmploymentStatus=''
                    IsPrivileged=$false; Tier=''; Groups=''
                    ComplianceStatus=''; RiskLevel=''; RiskScore=0; RiskScoreRaw=0; RiskDensity=0; HygieneIssueCount=0; RecommendedAction=''
                }
            }

                $enrichedRows.Add([PSCustomObject]@{
                    EntityId          = $f.EntityId
                    UPN               = $ctx.UPN
                    DisplayName       = $ctx.DisplayName
                    EntityType        = $ctx.EntityType
                    OnPremisesSynced  = $ctx.OnPremisesSynced     # <-- new
                    EmployeeType      = $ctx.EmployeeType
                    EmploymentStatus  = $ctx.EmploymentStatus
                    IsPrivileged      = $ctx.IsPrivileged
                    Tier              = $ctx.Tier
                    Groups            = $ctx.Groups
                    ComplianceStatus  = $ctx.ComplianceStatus
                    RiskLevel         = $ctx.RiskLevel
                    RiskScore         = $ctx.RiskScore
                    RiskScoreRaw      = $ctx.RiskScoreRaw
                    RiskDensity       = $ctx.RiskDensity
                    HygieneIssueCount = $ctx.HygieneIssueCount
                    RecommendedAction = $ctx.RecommendedAction
                    RuleId            = $f.RuleId
                    Category          = $f.Category
                    Severity          = $f.Severity
                    Weight            = $f.Weight
                    Blocking          = $f.Blocking
                    Details           = $f.Details
                    Timestamp         = $f.Timestamp
                    Mode              = $f.Mode
})
            }

            $enrichedRows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "  [Export] CSV  → $csvPath" -ForegroundColor Gray
        }
        catch {
            Write-Warning "ReportGenerator: CSV export failed: $_"
        }
    }

    if ($ExportJson) {
        $payload = [PSCustomObject]@{
            RunTimestamp     = $runTimestamp
            Mode             = $mode
            ScanMode         = $ScanMode
            RulesEvaluated   = $RulesEvaluated
            Summary          = $summary
            Drift            = $drift
            EntityRiskStates = $userStates
        }
        $jsonPath = Join-Path $OutputDir "$($mode)_Report_$runTimestamp.json"
        try {
            $payload | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
            Write-Host "  [Export] JSON → $jsonPath" -ForegroundColor Gray
        }
        catch {
            Write-Warning "ReportGenerator: JSON export failed: $_"
        }
    }

    # Store Drift State
    if ($StoreDriftState -and $mode -eq 'FullScan') {
        Save-ReportLastRunState -StatePath $stateFilePath -Summary $summary -RunTimestamp $runTimestamp
        Write-Host "  [State] Drift baseline saved → $stateFilePath" -ForegroundColor Gray
    }

    Write-Host ''
}


#  Get-GovernanceMetrics  (programmatic access, no console output).

function Get-GovernanceMetrics {
    <#
    .SYNOPSIS
        Returns a structured governance metrics object without writing to console.
        Suitable for pipeline integration or scheduled task output.

    .PARAMETER ClassificationResult
        Output from Invoke-RiskClassification.

    .PARAMETER OutputDir
        Directory to read LastRunState.json from for drift comparison.
        Must match the OutputDir used in the corresponding Write-GovernanceReport call.
        Defaults to .\Output\ relative to the engine root.

    .OUTPUTS
        PSCustomObject — metrics object including drift if available.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $ClassificationResult,
        [Parameter()]          [string]         $OutputDir = $Script:DefaultOutputDir
    )

    $mode    = $ClassificationResult.Mode
    $summary = $ClassificationResult.Summary
    $drift   = $null

    if ($mode -eq 'FullScan') {
        $stateFilePath = Join-Path $OutputDir 'LastRunState.json'
        $previousState = Load-ReportLastRunState -StatePath $stateFilePath
        $drift = Calculate-ReportDriftTrend -Current $summary -Previous $previousState
    }

    return [PSCustomObject]@{
        Mode        = $mode
        Summary     = $summary
        Drift       = $drift
        GeneratedAt = [datetime]::UtcNow.ToString('o')
    }
}