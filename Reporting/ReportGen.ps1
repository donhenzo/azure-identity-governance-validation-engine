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

# ──────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

$Script:DefaultOutputDir  = Join-Path $PSScriptRoot 'Output'
$Script:LastRunStateFile  = Join-Path $Script:DefaultOutputDir 'LastRunState.json'

# ──────────────────────────────────────────────────────────────────────────────
#  PRIVATE HELPERS
# ──────────────────────────────────────────────────────────────────────────────

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
        [string]       $StatePath,
        [PSCustomObject] $Summary,
        [string]       $RunTimestamp
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
            Available     = $false
            PreviousRun   = $null
            CompliantDelta = $null
            RiskTrendPct  = $null
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
        Available        = $true
        PreviousRun      = $Previous.RunTimestamp
        PreviousCompliant = $Previous.TotalCompliant
        CurrentCompliant = $Current.TotalCompliant
        CompliantDelta   = $Current.TotalCompliant - $Previous.TotalCompliant
        RiskTrendPct     = $delta
        RiskTrendText    = $trendText
    }
}

function Format-ReportSeverityBar {
    <# Produces a simple ASCII distribution bar for console output. #>
    param([int]$Blocking, [int]$NonCompliant, [int]$Compliant)
    return "  Blocking: $Blocking  |  NonCompliant: $NonCompliant  |  Compliant: $Compliant"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PUBLIC — PreProvision Report
# ──────────────────────────────────────────────────────────────────────────────

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

    $nameLabel = if ($TargetDisplayName) { "'$TargetDisplayName'" } else { $ClassificationResult.EntityId }
    $decisionColor = if ($ClassificationResult.Decision -eq 'Pass') { 'Green' } else { 'Red' }

    Write-Host ''
    Write-Host '══════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host "  PRE-PROVISION EVALUATION — $nameLabel" -ForegroundColor Cyan
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

# ──────────────────────────────────────────────────────────────────────────────
#  PUBLIC — FullScan / DriftOnly Report
# ──────────────────────────────────────────────────────────────────────────────

function Write-GovernanceReport {
    <#
    .SYNOPSIS
        Writes a full governance metrics report to the console and exports
        findings to CSV and JSON.

    .PARAMETER ClassificationResult
        Output from Invoke-RiskClassification -Mode FullScan or DriftOnly.

    .PARAMETER OutputDir
        Directory for exported files. Defaults to .\Output\

    .PARAMETER ExportCsv
        Switch: export findings to CSV.

    .PARAMETER ExportJson
        Switch: export findings to JSON.

    .PARAMETER StoreDriftState
        Switch: save current run state for drift comparison on next run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $ClassificationResult,
        [Parameter()]          [string]         $OutputDir      = $Script:DefaultOutputDir,
        [Parameter()]          [switch]         $ExportCsv,
        [Parameter()]          [switch]         $ExportJson,
        [Parameter()]          [switch]         $StoreDriftState,
        # EntityId → {UPN, DisplayName, EntityType, IsPrivileged, Tier, Groups, RiskLevel, RiskScore}
        # Built by ValidationEngine.ps1 where identity snapshot and classification results coexist.
        [Parameter()]          [hashtable]      $EnrichmentMap  = @{}
    )

    Ensure-ReportOutputDirectory -Path $OutputDir

    $runTimestamp = [datetime]::UtcNow.ToString('yyyyMMdd_HHmmss')
    $mode         = $ClassificationResult.Mode
    $summary      = $ClassificationResult.Summary
    $userStates   = $ClassificationResult.EntityRiskStates

    # ── Load Previous State for Drift ────────────────────────────────────────
    $previousState = Load-ReportLastRunState -StatePath $Script:LastRunStateFile
    $drift         = $null

    if ($mode -eq 'FullScan') {
        $drift = Calculate-ReportDriftTrend -Current $summary -Previous $previousState
    }

    # ── Console Output ────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host "║        GOVERNANCE VALIDATION REPORT  [$mode]" -ForegroundColor Cyan
    Write-Host "║        Run: $runTimestamp UTC" -ForegroundColor Cyan
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''

    if ($mode -eq 'FullScan') {

        Write-Host '  IDENTITY OVERVIEW' -ForegroundColor White
        Write-Host "    Total Identities Evaluated : $($summary.TotalIdentities)"
        Write-Host "    Compliant                  : $($summary.TotalCompliant)  ($($summary.PercentCompliant)%)" -ForegroundColor Green
        Write-Host "    Non-Compliant              : $($summary.TotalNonCompliant)" -ForegroundColor Yellow
        Write-Host "    Blocking                   : $($summary.TotalBlocking)"     -ForegroundColor Red
        Write-Host ''
        Write-Host '  PRIVILEGE & ARCHITECTURE' -ForegroundColor White
        Write-Host "    Privileged Identities      : $($summary.TotalPrivileged)  ($($summary.PercentPrivileged)%)"
        Write-Host "    Architecture Violations    : $($summary.TotalArchitectureViolations)"
        Write-Host "    Direct RBAC Assignments    : $($summary.TotalDirectRBACAssignments)"
        Write-Host ''

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

    # ── Critical/High Users Spotlight ────────────────────────────────────────
    $spotlightUsers = @($userStates |
        Where-Object { $_.ComplianceStatus -in @('Blocking', 'NonCompliant') } |
        Sort-Object RiskScore -Descending |
        Select-Object -First 10)

    if ($spotlightUsers.Count -gt 0) {
        Write-Host '  TOP RISK ENTITIES (Critical / High Risk)' -ForegroundColor Yellow
        foreach ($u in $spotlightUsers) {
            $color   = if ($u.ComplianceStatus -eq 'Blocking') { 'Red' } else { 'DarkYellow' }
            $ctx     = if ($EnrichmentMap.ContainsKey($u.EntityId)) { $EnrichmentMap[$u.EntityId] } else { $null }
            $label   = if ($ctx -and $ctx.UPN)         { $ctx.UPN         } else { $u.EntityId }
            $name    = if ($ctx -and $ctx.DisplayName) { $ctx.DisplayName } else { $u.EntityType }
            $tier    = if ($ctx -and $ctx.Tier)        { $ctx.Tier        } else { 'N/A' }
            Write-Host ("    [{0,-10}] Score: {1,5}  Density: {2,5}  Violations: {3,3}  Tier: {4,-14}  {5} ({6})" -f `
                $u.ComplianceStatus, $u.RiskScore, $u.RiskDensity, $u.ViolationCount, $tier, $label, $name) -ForegroundColor $color
        }
        Write-Host ''
    }

    Write-Host '══════════════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host ''

    # ── Export Findings ───────────────────────────────────────────────────────
    # Flatten all findings from all entity risk states into one list
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($u in $userStates) {
        foreach ($f in $u.Findings) {
            $allFindings.Add($f)
        }
    }

    if ($ExportCsv -and $allFindings.Count -gt 0) {
        $csvPath = Join-Path $OutputDir "$($mode)_Findings_$runTimestamp.csv"
        try {
            # Build enriched rows: join finding fields with identity context from enrichment map.
            # Each row represents one rule violation with full human-readable context.
            $enrichedRows = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($f in $allFindings) {

                $ctx = if ($EnrichmentMap.ContainsKey($f.EntityId)) {
                    $EnrichmentMap[$f.EntityId]
                } else {
                    [PSCustomObject]@{
                        UPN=''; DisplayName=''; EntityType=$f.EntityType
                        EmployeeType=''; EmploymentStatus=''
                        IsPrivileged=$false; Tier=''; Groups=''
                        ComplianceStatus=''; RiskLevel=''; RiskScore=0; RiskScoreRaw=0; RiskDensity=0; HygieneIssueCount=0; RecommendedAction=''
                    }
                }

                $enrichedRows.Add([PSCustomObject]@{
                    # Identity context
                    EntityId         = $f.EntityId
                    UPN              = $ctx.UPN
                    DisplayName      = $ctx.DisplayName
                    EntityType       = $ctx.EntityType
                    EmployeeType     = $ctx.EmployeeType
                    EmploymentStatus = $ctx.EmploymentStatus
                    IsPrivileged     = $ctx.IsPrivileged
                    Tier             = $ctx.Tier
                    Groups           = $ctx.Groups
                    # Risk classification
                    ComplianceStatus  = $ctx.ComplianceStatus
                    RiskLevel         = $ctx.RiskLevel
                    RiskScore         = $ctx.RiskScore
                    RiskScoreRaw      = $ctx.RiskScoreRaw
                    RiskDensity       = $ctx.RiskDensity
                    HygieneIssueCount = $ctx.HygieneIssueCount
                    RecommendedAction = $ctx.RecommendedAction
                    # Finding detail
                    RuleId       = $f.RuleId
                    Category     = $f.Category
                    Severity     = $f.Severity
                    Weight       = $f.Weight
                    Blocking     = $f.Blocking
                    Details      = $f.Details
                    Timestamp    = $f.Timestamp
                    Mode         = $f.Mode
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

    # ── Store Drift State ─────────────────────────────────────────────────────
    if ($StoreDriftState -and $mode -eq 'FullScan') {
        Save-ReportLastRunState -StatePath $Script:LastRunStateFile -Summary $summary -RunTimestamp $runTimestamp
        Write-Host "  [State] Run state saved for next drift comparison." -ForegroundColor Gray
    }

    Write-Host ''
}

# ──────────────────────────────────────────────────────────────────────────────
#  PUBLIC — Get-GovernanceMetrics  (programmatic access, no console output)
# ──────────────────────────────────────────────────────────────────────────────

function Get-GovernanceMetrics {
    <#
    .SYNOPSIS
        Returns a structured governance metrics object without writing to console.
        Suitable for pipeline integration or scheduled task output.

    .PARAMETER ClassificationResult
        Output from Invoke-RiskClassification.

    .OUTPUTS
        PSCustomObject — metrics object including drift if available.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [PSCustomObject] $ClassificationResult
    )

    $mode    = $ClassificationResult.Mode
    $summary = $ClassificationResult.Summary
    $drift   = $null

    if ($mode -eq 'FullScan') {
        $previousState = Load-ReportLastRunState -StatePath $Script:LastRunStateFile
        $drift = Calculate-ReportDriftTrend -Current $summary -Previous $previousState
    }

    return [PSCustomObject]@{
        Mode         = $mode
        Summary      = $summary
        Drift        = $drift
        GeneratedAt  = [datetime]::UtcNow.ToString('o')
    }
}