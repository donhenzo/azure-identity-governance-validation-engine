<#
.SYNOPSIS
    Migrate-LegacyGroups.ps1 — One-time remediation pass to move existing users
    from legacy groups into the standardised JML group structure.

.DESCRIPTION
    This script is NOT a JML lifecycle event. It is a one-time migration to bring
    the existing tenant population into compliance with the new group architecture
    before Phase 1 provisioning takes over as the authoritative source.

    For each legacy group it:
        1. Enumerates all current members
        2. Looks up each member's department and employment type from Entra ID
        3. Routes them to the correct standardised group(s) based on the mapping table
        4. Checks before adding — fully idempotent, safe to re-run
        5. Logs every action with outcome to a structured log
        6. Exports unresolved members (missing dept/type) to a CSV for manual review

    LEGACY GROUPS PROCESSED:
        Direct mappings  — Sales Team, SalesManagers, HR_Grp, HR_Mangers,
                           Finance_Access, Finance_Managers, Security_Eng_team,
                           IT_Admins
        Department-based — ALLStaff (routes by department + employment type)
        Executive        — Exec_Team (routes by department to Executive groups)

    GROUPS LEFT UNTOUCHED:
        grp-az-* and RBAC-admin — Azure RBAC / service principal enforced groups.
        These are not identity governance groups and must not be modified.

    # Preview what the script will do — no changes made
    .\Migrate-LegacyGroups.ps1 -DryRun

    # Run the migration
    .\Migrate-LegacyGroups.ps1

.NOTES
    Requires: Connect-MgGraph with scopes:
        User.Read.All, Group.Read.All, GroupMember.ReadWrite.All
    Run Connect-MgGraph before executing this script.
    This script must be run once only. After migration, the JML engine
    owns all group assignments for new identities.
#>

[CmdletBinding()]
param(
    [switch] $DryRun,
    [string] $OutputDir = (Join-Path $PSScriptRoot 'MigrationOutput')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# PERFORMANCE + IDEMPOTENCY CACHES=
# Prevent duplicate adds in same execution
$PlannedAdds = [System.Collections.Generic.HashSet[string]]::new()

# Cache group membership lookups to avoid repeated Graph queries
$GroupMembershipCache = @{}


# OUTPUT SETUP
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$runTimestamp    = [datetime]::UtcNow.ToString('yyyyMMdd_HHmmss')
$logPath         = Join-Path $OutputDir "Migration_Log_$runTimestamp.csv"
$unresolvedPath  = Join-Path $OutputDir "Migration_Unresolved_$runTimestamp.csv"

$logRows        = [System.Collections.Generic.List[PSCustomObject]]::new()
$unresolvedRows = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-MigrationLog {
    param(
        [string] $LegacyGroup,
        [string] $UserId,
        [string] $UPN,
        [string] $DisplayName,
        [string] $Department,
        [string] $EmploymentType,
        [string] $TargetGroup,
        [string] $TargetGroupId,
        [string] $Action,
        [string] $Reason = ''
    )

    $row = [PSCustomObject]@{
        Timestamp      = [datetime]::UtcNow.ToString('o')
        LegacyGroup    = $LegacyGroup
        UserId         = $UserId
        UPN            = $UPN
        DisplayName    = $DisplayName
        Department     = $Department
        EmploymentType = $EmploymentType
        TargetGroup    = $TargetGroup
        TargetGroupId  = $TargetGroupId
        Action         = $Action
        Reason         = $Reason
        DryRun         = $DryRun.IsPresent
    }

    $logRows.Add($row)

    $color = switch ($Action) {
        'Added'    { 'Green'  }
        'WouldAdd' { 'Cyan'   }
        'Skipped'  { 'Gray'   }
        'Failed'   { 'Red'    }
        default    { 'White'  }
    }

    Write-Host ("  [{0,-9}] {1,-40} → {2}" -f $Action, $UPN, $TargetGroup) -ForegroundColor $color
}

function Write-UnresolvedLog {
    param(
        [string] $LegacyGroup,
        [string] $UserId,
        [string] $UPN,
        [string] $DisplayName,
        [string] $Department,
        [string] $EmploymentType,
        [string] $Reason
    )

    $unresolvedRows.Add([PSCustomObject]@{
        Timestamp      = [datetime]::UtcNow.ToString('o')
        LegacyGroup    = $LegacyGroup
        UserId         = $UserId
        UPN            = $UPN
        DisplayName    = $DisplayName
        Department     = $Department
        EmploymentType = $EmploymentType
        Reason         = $Reason
    })

    Write-Host ("  [Unresolved] {0,-40} — {1}" -f $UPN, $Reason) -ForegroundColor Yellow
}



# GROUP ID REFERENCE TABLE
$Groups = @{
    SG_Sales_Core        = '111fdfb6-1709-4987-8818-b66417d89f91'
    SG_Sales_Staff       = '62232728-47eb-4308-b3d3-91e4cb8bb0b4'
    SG_Sales_Manager     = '0c67c63b-a6e2-4bf6-b4a0-3a860384cf08'
    SG_Sales_Contractor  = '3f36950a-2f27-4d09-952e-48cf4a4ef692'
    SG_Sales_Intern      = '144af628-c5a7-4e1f-91b3-010b8ae9469e'

    SG_HR_Core           = '3005476d-7190-480a-a23f-ab65f0d2061e'
    SG_HR_Staff          = '999749f5-e34a-47ce-be6e-22bba169fce0'
    SG_HR_Manager        = 'fd309a8a-e303-4ac4-bd03-454a5d8048c7'
    SG_HR_Contractor     = '889ab9db-381e-4bc3-a222-fad441d4cbe0'
    SG_HR_Intern         = '4fc58c2f-53da-488a-9afa-99b0589d1a96'

    SG_Finance_Core      = '8410d4d1-fe60-413f-9d2d-6d33200c6517'
    SG_Finance_Staff     = '5d33063f-53da-4d01-a87c-1d5f460b840b'
    SG_Finance_Manager   = 'c2b66a61-cf52-4cf8-b9fe-7557efcf7853'
    SG_Finance_Contractor= 'daafe4fc-0f91-46c8-9457-5094c6ebab73'
    SG_Finance_Intern    = 'c9edbc72-f5f5-4ee0-afef-45204e7da153'

    SG_IT_Core           = 'fc34a451-4897-4139-88e8-6464cd2f4a85'
    SG_IT_Staff          = 'f24a7cb3-6c38-4220-8637-5927ec8bed94'
    SG_IT_Manager        = '49349779-b40b-4989-af0c-bf2c78c459e1'
    SG_IT_Contractor     = '1d856a92-5b08-4527-8a17-83aca9f97af1'
    SG_IT_Intern         = '1eb1bfb5-27e2-44de-98c9-72a5d2badfc2'

    SG_Engineering_Core       = 'fa63d51b-f81c-4b2b-a658-31f6befe5a49'
    SG_Engineering_Staff      = '956720f7-8f66-4987-bf47-4998c839ba00'
    SG_Engineering_Manager    = 'b7bfed9d-4531-4891-8347-1fed3c2f8d36'
    SG_Engineering_Contractor = '27061e09-c0a4-4cd6-91b3-ddb7714a37bd'
    SG_Engineering_Intern     = 'e561e33b-2793-4fa9-8b71-1c6a68b5fd58'

    SG_Security_Core       = 'f6daa7ee-7873-4317-8b5b-59a059564fa7'
    SG_Security_Engineer   = 'a69f3794-1409-4df1-980f-7ee45504b157'
    SG_Security_Contractor = 'd7676462-a16b-46e9-8237-a13fe98b5980'
    SG_Security_HOD        = 'f67c852c-74bd-4565-8ffc-d54a8da7f18e'

    SG_Executive_Core    = '75b7b337-6797-441a-802c-28fe3ee4e43b'
    SG_Executive_HR      = '28d91ebd-77f2-4ad4-a767-8ba11ddc24ff'
    SG_Executive_Sales   = '42afeb6e-d72c-4e3b-a155-614f40f0f042'
    SG_Executive_Finance = 'b63364e3-fdfb-42fd-8c01-869d35aa070d'

    CA_Standard_Users    = '3e67ae85-f761-46ce-b958-54ec38625736'
    CA_Contractors       = '081cf46b-806b-449f-a838-98cc0433b5d1'
    CA_Executives        = '6ef01a0c-1f43-4408-b997-87ef107d4f16'
    LIC_M365_E3          = 'd18f0b08-1ab6-462b-95ff-707c88cc7e0b'
    LIC_Finance_Addon    = 'ddfd7df2-a436-4f44-b8df-f90b95189958'
}



# DEPARTMENT LOOKUP TABLES
$DeptToCoreGroup = @{
    'sales'                  = 'SG_Sales_Core'
    'human resources'        = 'SG_HR_Core'
    'hr'                     = 'SG_HR_Core'
    'finance'                = 'SG_Finance_Core'
    'information technology' = 'SG_IT_Core'
    'it'                     = 'SG_IT_Core'
    'engineering'            = 'SG_Engineering_Core'
    'security'               = 'SG_Security_Core'
}

$DeptToManagerGroup = @{
    'sales'                  = 'SG_Sales_Manager'
    'human resources'        = 'SG_HR_Manager'
    'hr'                     = 'SG_HR_Manager'
    'finance'                = 'SG_Finance_Manager'
    'information technology' = 'SG_IT_Manager'
    'it'                     = 'SG_IT_Manager'
    'engineering'            = 'SG_Engineering_Manager'
    'security'               = 'SG_Security_HOD'
}

$DeptToStaffGroup = @{
    'sales'                  = 'SG_Sales_Staff'
    'human resources'        = 'SG_HR_Staff'
    'hr'                     = 'SG_HR_Staff'
    'finance'                = 'SG_Finance_Staff'
    'information technology' = 'SG_IT_Staff'
    'it'                     = 'SG_IT_Staff'
    'engineering'            = 'SG_Engineering_Staff'
    'security'               = 'SG_Security_Engineer'
}

$DeptToContractorGroup = @{
    'sales'                  = 'SG_Sales_Contractor'
    'human resources'        = 'SG_HR_Contractor'
    'hr'                     = 'SG_HR_Contractor'
    'finance'                = 'SG_Finance_Contractor'
    'information technology' = 'SG_IT_Contractor'
    'it'                     = 'SG_IT_Contractor'
    'engineering'            = 'SG_Engineering_Contractor'
    'security'               = 'SG_Security_Contractor'
}

$DeptToInternGroup = @{
    'sales'                  = 'SG_Sales_Intern'
    'human resources'        = 'SG_HR_Intern'
    'hr'                     = 'SG_HR_Intern'
    'finance'                = 'SG_Finance_Intern'
    'information technology' = 'SG_IT_Intern'
    'it'                     = 'SG_IT_Intern'
    'engineering'            = 'SG_Engineering_Intern'
}

$DeptToExecutiveGroup = @{
    'sales'                  = 'SG_Executive_Sales'
    'human resources'        = 'SG_Executive_HR'
    'hr'                     = 'SG_Executive_HR'
    'finance'                = 'SG_Executive_Finance'
}



# EMPLOYMENT TYPE NORMALISATION
function Resolve-EmploymentType {
    param([string] $RawValue)

    $cleaned = ($RawValue ?? '').Trim().ToLower()

    $resolved = switch -Regex ($cleaned) {
        '^(employee|full.?time|fte|permanent|staff)$' { 'Employee'   }
        '^(contractor|contract|vendor|consultant)$'   { 'Contractor' }
        '^(intern|internship|graduate|apprentice)$'   { 'Intern'     }
        '^(manager|senior manager|head of|director)$' { 'Manager'    }
        default                                        { ''           }
    }

    return $resolved
}



# CORE HELPERS

function Get-GroupMembers {
    param([string] $GroupId)

    $members = [System.Collections.Generic.List[PSCustomObject]]::new()
    $page = Get-MgGroupMember -GroupId $GroupId -All `
        -Property 'id,displayName,userPrincipalName,department,employeeType,employeeId' `
        -ErrorAction Stop

    foreach ($m in $page) {
        if ($m.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.user') { continue }

        $members.Add([PSCustomObject]@{
            UserId       = $m.Id
            DisplayName  = ($m.AdditionalProperties['displayName']        ?? '').Trim()
            UPN          = ($m.AdditionalProperties['userPrincipalName']  ?? '').Trim()
            Department   = ($m.AdditionalProperties['department']         ?? '').Trim()
            EmployeeType = ($m.AdditionalProperties['employeeType']       ?? '').Trim()
        })
    }

    return $members
}

function Test-GroupMember {
    param([string] $GroupId, [string] $UserId)

    if (-not $GroupMembershipCache.ContainsKey($GroupId)) {

        try {
            $members = Get-MgGroupMember -GroupId $GroupId -All -Property 'id' -ErrorAction Stop |
                       Select-Object -ExpandProperty Id

            $GroupMembershipCache[$GroupId] = $members
        }
        catch {
            $GroupMembershipCache[$GroupId] = @()
        }
    }

    return $GroupMembershipCache[$GroupId] -contains $UserId
}

function Add-UserToGroup {
    param(
        [string] $UserId,
        [string] $UPN,
        [string] $DisplayName,
        [string] $Department,
        [string] $EmploymentType,
        [string] $TargetGroupName,
        [string] $LegacyGroupName
    )

    $groupId = $Groups[$TargetGroupName]

    if (-not $groupId) {
        Write-MigrationLog -LegacyGroup $LegacyGroupName -UserId $UserId -UPN $UPN `
            -DisplayName $DisplayName -Department $Department `
            -EmploymentType $EmploymentType -TargetGroup $TargetGroupName `
            -TargetGroupId '' -Action 'Failed' `
            -Reason "Group ID not found in reference table for '$TargetGroupName'"
        return
    }

    $key = "$UserId|$groupId"

    # Prevent duplicate attempts in same run
    if ($PlannedAdds.Contains($key)) {
        Write-MigrationLog -LegacyGroup $LegacyGroupName -UserId $UserId -UPN $UPN `
            -DisplayName $DisplayName -Department $Department `
            -EmploymentType $EmploymentType -TargetGroup $TargetGroupName `
            -TargetGroupId $groupId -Action 'Skipped' `
            -Reason 'Already planned in this run'
        return
    }

    if (Test-GroupMember -GroupId $groupId -UserId $UserId) {
        Write-MigrationLog -LegacyGroup $LegacyGroupName -UserId $UserId -UPN $UPN `
            -DisplayName $DisplayName -Department $Department `
            -EmploymentType $EmploymentType -TargetGroup $TargetGroupName `
            -TargetGroupId $groupId -Action 'Skipped' -Reason 'Already a member'
        return
    }

    if ($DryRun) {

        Write-MigrationLog -LegacyGroup $LegacyGroupName -UserId $UserId -UPN $UPN `
            -DisplayName $DisplayName -Department $Department `
            -EmploymentType $EmploymentType -TargetGroup $TargetGroupName `
            -TargetGroupId $groupId -Action 'WouldAdd'

        $PlannedAdds.Add($key) | Out-Null
        return
    }

    try {

        $bodyParam = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$UserId" }

        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/members/`$ref" `
            -Body $bodyParam -ErrorAction Stop

        Write-MigrationLog -LegacyGroup $LegacyGroupName -UserId $UserId -UPN $UPN `
            -DisplayName $DisplayName -Department $Department `
            -EmploymentType $EmploymentType -TargetGroup $TargetGroupName `
            -TargetGroupId $groupId -Action 'Added'

        $PlannedAdds.Add($key) | Out-Null

        # Update membership cache
        if ($GroupMembershipCache.ContainsKey($groupId)) {
            $GroupMembershipCache[$groupId] += $UserId
        }

    }
    catch {

        Write-MigrationLog -LegacyGroup $LegacyGroupName -UserId $UserId -UPN $UPN `
            -DisplayName $DisplayName -Department $Department `
            -EmploymentType $EmploymentType -TargetGroup $TargetGroupName `
            -TargetGroupId $groupId -Action 'Failed' -Reason $_.Exception.Message
    }
}


# SHARED EMPLOYMENT-TYPE ROUTING
# Assigns sub-groups, CA group, and license based on resolved employment type.
# Used by both Invoke-DirectMigration and Invoke-DepartmentBasedMigration
# so the logic lives in one place.
function Invoke-EmploymentTypeRouting {
    param(
        [string] $UserId,
        [string] $UPN,
        [string] $DisplayName,
        [string] $Department,
        [string] $DeptKey,
        [string] $EmploymentType,
        [string] $LegacyGroupName
    )

    switch ($EmploymentType) {
        'Employee' {
            if ($DeptToStaffGroup.ContainsKey($DeptKey)) {
                Add-UserToGroup -UserId $UserId -UPN $UPN -DisplayName $DisplayName `
                    -Department $Department -EmploymentType $EmploymentType `
                    -TargetGroupName $DeptToStaffGroup[$DeptKey] -LegacyGroupName $LegacyGroupName
            }
            Add-UserToGroup -UserId $UserId -UPN $UPN -DisplayName $DisplayName `
                -Department $Department -EmploymentType $EmploymentType `
                -TargetGroupName 'CA_Standard_Users' -LegacyGroupName $LegacyGroupName
        }
        'Manager' {
            # Manager gets Staff AND Manager sub-groups
            if ($DeptToStaffGroup.ContainsKey($DeptKey)) {
                Add-UserToGroup -UserId $UserId -UPN $UPN -DisplayName $DisplayName `
                    -Department $Department -EmploymentType $EmploymentType `
                    -TargetGroupName $DeptToStaffGroup[$DeptKey] -LegacyGroupName $LegacyGroupName
            }
            if ($DeptToManagerGroup.ContainsKey($DeptKey)) {
                Add-UserToGroup -UserId $UserId -UPN $UPN -DisplayName $DisplayName `
                    -Department $Department -EmploymentType $EmploymentType `
                    -TargetGroupName $DeptToManagerGroup[$DeptKey] -LegacyGroupName $LegacyGroupName
            }
            Add-UserToGroup -UserId $UserId -UPN $UPN -DisplayName $DisplayName `
                -Department $Department -EmploymentType $EmploymentType `
                -TargetGroupName 'CA_Standard_Users' -LegacyGroupName $LegacyGroupName
        }
        'Contractor' {
            if ($DeptToContractorGroup.ContainsKey($DeptKey)) {
                Add-UserToGroup -UserId $UserId -UPN $UPN -DisplayName $DisplayName `
                    -Department $Department -EmploymentType $EmploymentType `
                    -TargetGroupName $DeptToContractorGroup[$DeptKey] -LegacyGroupName $LegacyGroupName
            }
            Add-UserToGroup -UserId $UserId -UPN $UPN -DisplayName $DisplayName `
                -Department $Department -EmploymentType $EmploymentType `
                -TargetGroupName 'CA_Contractors' -LegacyGroupName $LegacyGroupName
        }
        'Intern' {
            if ($DeptToInternGroup.ContainsKey($DeptKey)) {
                Add-UserToGroup -UserId $UserId -UPN $UPN -DisplayName $DisplayName `
                    -Department $Department -EmploymentType $EmploymentType `
                    -TargetGroupName $DeptToInternGroup[$DeptKey] -LegacyGroupName $LegacyGroupName
            }
            Add-UserToGroup -UserId $UserId -UPN $UPN -DisplayName $DisplayName `
                -Department $Department -EmploymentType $EmploymentType `
                -TargetGroupName 'CA_Standard_Users' -LegacyGroupName $LegacyGroupName
        }
    }

    # M365 E3 baseline — all employment types
    Add-UserToGroup -UserId $UserId -UPN $UPN -DisplayName $DisplayName `
        -Department $Department -EmploymentType $EmploymentType `
        -TargetGroupName 'LIC_M365_E3' -LegacyGroupName $LegacyGroupName

    # Finance addon license
    if ($DeptKey -eq 'finance') {
        Add-UserToGroup -UserId $UserId -UPN $UPN -DisplayName $DisplayName `
            -Department $Department -EmploymentType $EmploymentType `
            -TargetGroupName 'LIC_Finance_Addon' -LegacyGroupName $LegacyGroupName
    }
}



# MIGRATION FUNCTIONS
function Invoke-DirectMigration {
    <#
    Migrates members of a direct-mapping legacy group.

    Employment type gates which sub-groups the user receives.
    Users with null/unresolvable employment type are skipped to the
    unresolved log — we cannot determine correct routing without it.

    Incompatible assignments (e.g. Intern or Contractor in a Manager-tier
    legacy group) are blocked from the Manager sub-group. The user still
    receives the Core group only. The mismatch is written to the unresolved
    CSV for manual review.

    Parameters:
        LegacyGroupId   — Object ID of the source legacy group
        LegacyGroupName — Display name for log output
        DeptCoreGroup   — Core group all members receive (dept baseline)
        DeptKey         — Lowercase department key for sub-group lookup
        LegacyGroupTier — Implied tier of the legacy group: Core|Staff|Manager
                          Used to detect employment type mismatches
    #>
    param(
        [string] $LegacyGroupId,
        [string] $LegacyGroupName,
        [string] $DeptCoreGroup,
        [string] $DeptKey,
        [string] $LegacyGroupTier = 'Core'
    )

    Write-Host "`n  Processing: $LegacyGroupName → $DeptCoreGroup (tier: $LegacyGroupTier)" -ForegroundColor White

    $members = Get-GroupMembers -GroupId $LegacyGroupId

    foreach ($member in $members) {

        $empType = Resolve-EmploymentType -RawValue $member.EmployeeType

        # Legacy Manager groups override incorrect HR employment type
        if ($LegacyGroupTier -eq 'Manager' -and $empType -ne 'Manager') {
             $empType = 'Manager'
         }

        # Hard block — null or unrecognised employment type cannot be routed.
        # Written to unresolved CSV for manual fix before re-running.
        if ([string]::IsNullOrWhiteSpace($empType)) {
            Write-UnresolvedLog -LegacyGroup $LegacyGroupName -UserId $member.UserId `
                -UPN $member.UPN -DisplayName $member.DisplayName `
                -Department $member.Department -EmploymentType $member.EmployeeType `
                -Reason "Employment type '$($member.EmployeeType)' could not be resolved — manual review required"
            continue
        }

        # Mismatch guard — Intern or Contractor must not be migrated into a Manager group.
        # This is a data quality problem in the legacy group, not a valid assignment.
        # The user still receives the Core group as a baseline — only Manager sub-group is blocked.
        $incompatible = ($LegacyGroupTier -eq 'Manager' -and $empType -in @('Intern', 'Contractor'))

        if ($incompatible) {
            Write-UnresolvedLog -LegacyGroup $LegacyGroupName -UserId $member.UserId `
                -UPN $member.UPN -DisplayName $member.DisplayName `
                -Department $member.Department -EmploymentType $empType `
                -Reason "Employment type '$empType' is incompatible with Manager-tier legacy group. Routed to Core only — manual Manager group assignment required if appropriate."
        }

        # Core group — all members receive this regardless of employment type or mismatch
        Add-UserToGroup -UserId $member.UserId -UPN $member.UPN `
            -DisplayName $member.DisplayName -Department $member.Department `
            -EmploymentType $empType -TargetGroupName $DeptCoreGroup `
            -LegacyGroupName $LegacyGroupName

        # Sub-groups, CA, and license routing — skipped for incompatible mismatches.
        # Mismatch users get Core only; everything else requires a human decision.
        if (-not $incompatible) {
            Invoke-EmploymentTypeRouting `
                -UserId $member.UserId -UPN $member.UPN -DisplayName $member.DisplayName `
                -Department $member.Department -DeptKey $DeptKey -EmploymentType $empType `
                -LegacyGroupName $LegacyGroupName
        }
    }
}

function Invoke-DepartmentBasedMigration {
    <#
    Migrates ALLStaff members by looking up each member's department
    and employment type, then routing to the correct standardised groups.
    Members with no department or unresolvable employment type are written
    to the unresolved CSV for manual review.
    #>
    param(
        [string] $LegacyGroupId,
        [string] $LegacyGroupName
    )

    Write-Host "`n  Processing: $LegacyGroupName (department-based routing)" -ForegroundColor White

    $members = Get-GroupMembers -GroupId $LegacyGroupId

    foreach ($member in $members) {

        $deptKey = $member.Department.Trim().ToLower()
        $empType = Resolve-EmploymentType -RawValue $member.EmployeeType

        # Cannot route without a department
        if ([string]::IsNullOrWhiteSpace($deptKey)) {
            Write-UnresolvedLog -LegacyGroup $LegacyGroupName -UserId $member.UserId `
                -UPN $member.UPN -DisplayName $member.DisplayName `
                -Department '' -EmploymentType $empType `
                -Reason 'Department attribute is empty — cannot determine target group'
            continue
        }

        # Cannot route without a resolved employment type
        if ([string]::IsNullOrWhiteSpace($empType)) {
            Write-UnresolvedLog -LegacyGroup $LegacyGroupName -UserId $member.UserId `
                -UPN $member.UPN -DisplayName $member.DisplayName `
                -Department $member.Department -EmploymentType $member.EmployeeType `
                -Reason "Employment type '$($member.EmployeeType)' could not be resolved — manual review required"
            continue
        }

        # Department must map to a standardised Core group
        if (-not $DeptToCoreGroup.ContainsKey($deptKey)) {
            Write-UnresolvedLog -LegacyGroup $LegacyGroupName -UserId $member.UserId `
                -UPN $member.UPN -DisplayName $member.DisplayName `
                -Department $member.Department -EmploymentType $empType `
                -Reason "Department '$($member.Department)' has no standardised group mapping"
            continue
        }

        # Core group — baseline for all members in this department
        Add-UserToGroup -UserId $member.UserId -UPN $member.UPN `
            -DisplayName $member.DisplayName -Department $member.Department `
            -EmploymentType $empType -TargetGroupName $DeptToCoreGroup[$deptKey] `
            -LegacyGroupName $LegacyGroupName

        # Sub-groups, CA, and license based on employment type
        Invoke-EmploymentTypeRouting `
            -UserId $member.UserId -UPN $member.UPN -DisplayName $member.DisplayName `
            -Department $member.Department -DeptKey $deptKey -EmploymentType $empType `
            -LegacyGroupName $LegacyGroupName
    }
}

function Invoke-ExecutiveMigration {
    <#
    Migrates Exec_Team members to the Executive group structure.
    All execs receive SG_Executive_Core and CA_Executives.
    Department routes them to the department-specific executive group.
    Employment type is not a gate here — Exec_Team is an executive group
    and all members are treated as Manager tier by definition.
    #>
    param(
        [string] $LegacyGroupId,
        [string] $LegacyGroupName
    )

    Write-Host "`n  Processing: $LegacyGroupName (executive routing)" -ForegroundColor White

    $members = Get-GroupMembers -GroupId $LegacyGroupId

    foreach ($member in $members) {

        $deptKey = $member.Department.Trim().ToLower()

        # All executives get the baseline executive group, CA policy, and license
        Add-UserToGroup -UserId $member.UserId -UPN $member.UPN `
            -DisplayName $member.DisplayName -Department $member.Department `
            -EmploymentType 'Manager' -TargetGroupName 'SG_Executive_Core' `
            -LegacyGroupName $LegacyGroupName

        Add-UserToGroup -UserId $member.UserId -UPN $member.UPN `
            -DisplayName $member.DisplayName -Department $member.Department `
            -EmploymentType 'Manager' -TargetGroupName 'CA_Executives' `
            -LegacyGroupName $LegacyGroupName

        Add-UserToGroup -UserId $member.UserId -UPN $member.UPN `
            -DisplayName $member.DisplayName -Department $member.Department `
            -EmploymentType 'Manager' -TargetGroupName 'LIC_M365_E3' `
            -LegacyGroupName $LegacyGroupName

        # Department-specific executive group
        if ([string]::IsNullOrWhiteSpace($deptKey)) {
            Write-UnresolvedLog -LegacyGroup $LegacyGroupName -UserId $member.UserId `
                -UPN $member.UPN -DisplayName $member.DisplayName `
                -Department '' -EmploymentType 'Manager' `
                -Reason 'Department empty — assigned to SG_Executive_Core only, manual dept group assignment required'
            continue
        }

        if ($DeptToExecutiveGroup.ContainsKey($deptKey)) {
            Add-UserToGroup -UserId $member.UserId -UPN $member.UPN `
                -DisplayName $member.DisplayName -Department $member.Department `
                -EmploymentType 'Manager' -TargetGroupName $DeptToExecutiveGroup[$deptKey] `
                -LegacyGroupName $LegacyGroupName
        }
        else {
            Write-UnresolvedLog -LegacyGroup $LegacyGroupName -UserId $member.UserId `
                -UPN $member.UPN -DisplayName $member.DisplayName `
                -Department $member.Department -EmploymentType 'Manager' `
                -Reason "No executive group mapping for department '$($member.Department)'"
        }
    }
}



# MAIN — MIGRATION EXECUTION
$modeLabel = if ($DryRun) { 'DRY RUN — no changes will be made' } else { 'LIVE RUN — changes will be committed' }

Write-Host ''
Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
Write-Host "║  LEGACY GROUP MIGRATION                                      ║" -ForegroundColor Cyan
Write-Host "║  $($modeLabel.PadRight(60))║" -ForegroundColor $(if ($DryRun) { 'Yellow' } else { 'Cyan' })
Write-Host "║  Run: $($runTimestamp.PadRight(55))║" -ForegroundColor Cyan
Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan

# Direct mappings — IDs are authoritative, display names have whitespace issues

Invoke-DirectMigration `
    -LegacyGroupId   '4911823d-fe03-4667-be7b-9ecbd6d5ff15' `
    -LegacyGroupName 'Sales Team' `
    -DeptCoreGroup   'SG_Sales_Core' `
    -DeptKey         'sales' `
    -LegacyGroupTier 'Core'

Invoke-DirectMigration `
    -LegacyGroupId   'e9530981-ca8b-4e86-966d-3a4251420e87' `
    -LegacyGroupName 'SalesManagers' `
    -DeptCoreGroup   'SG_Sales_Core' `
    -DeptKey         'sales' `
    -LegacyGroupTier 'Manager'

Invoke-DirectMigration `
    -LegacyGroupId   'e15f7dc4-9901-4665-9b47-da9fc08bf731' `
    -LegacyGroupName 'HR_Grp' `
    -DeptCoreGroup   'SG_HR_Core' `
    -DeptKey         'human resources' `
    -LegacyGroupTier 'Core'

Invoke-DirectMigration `
    -LegacyGroupId   '28ce7bd2-e8bf-4d1d-9f98-382799c61a5e' `
    -LegacyGroupName 'HR_Mangers' `
    -DeptCoreGroup   'SG_HR_Core' `
    -DeptKey         'human resources' `
    -LegacyGroupTier 'Manager'

Invoke-DirectMigration `
    -LegacyGroupId   '0f3e9225-8740-49ce-94fe-25a0ca024065' `
    -LegacyGroupName 'Finance_Access' `
    -DeptCoreGroup   'SG_Finance_Core' `
    -DeptKey         'finance' `
    -LegacyGroupTier 'Core'

Invoke-DirectMigration `
    -LegacyGroupId   'c926c502-0d41-4f1f-8f20-0b4bdf09e0c4' `
    -LegacyGroupName 'Finance_Managers' `
    -DeptCoreGroup   'SG_Finance_Core' `
    -DeptKey         'finance' `
    -LegacyGroupTier 'Manager'

Invoke-DirectMigration `
    -LegacyGroupId   '70990760-8b3f-4321-aa49-0f3e41ac3adc' `
    -LegacyGroupName 'Security_Eng_team' `
    -DeptCoreGroup   'SG_Security_Core' `
    -DeptKey         'security' `
    -LegacyGroupTier 'Staff'

Invoke-DirectMigration `
    -LegacyGroupId   '2de0e284-5075-45d9-8aa1-32564e73222d' `
    -LegacyGroupName 'IT_Admins' `
    -DeptCoreGroup   'SG_IT_Core' `
    -DeptKey         'information technology' `
    -LegacyGroupTier 'Core'

# Department-based routing

Invoke-DepartmentBasedMigration `
    -LegacyGroupId   'a282289f-c98c-463a-b01c-ffbc94ba5ff5' `
    -LegacyGroupName 'ALLStaff'

# Executive routing

Invoke-ExecutiveMigration `
    -LegacyGroupId   'ac29d3af-aaf7-4110-ae98-0158f1fda722' `
    -LegacyGroupName 'Exec_Team'



# WRITE OUTPUTS
Write-Host ''
Write-Host '  Writing output files...' -ForegroundColor Gray

$logRows | Export-Csv -LiteralPath $logPath -NoTypeInformation -Encoding UTF8
Write-Host "  Log        → $logPath" -ForegroundColor Gray

if ($unresolvedRows.Count -gt 0) {
    $unresolvedRows | Export-Csv -LiteralPath $unresolvedPath -NoTypeInformation -Encoding UTF8
    Write-Host "  Unresolved → $unresolvedPath ($($unresolvedRows.Count) records require manual review)" -ForegroundColor Yellow
}
else {
    Write-Host '  Unresolved → none' -ForegroundColor Green
}



# SUMMARY
$added      = @($logRows | Where-Object { $_.Action -eq 'Added'    }).Count
$wouldAdd   = @($logRows | Where-Object { $_.Action -eq 'WouldAdd' }).Count
$skipped    = @($logRows | Where-Object { $_.Action -eq 'Skipped'  }).Count
$failed     = @($logRows | Where-Object { $_.Action -eq 'Failed'   }).Count
$unresolved = $unresolvedRows.Count

Write-Host ''
Write-Host '══════════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host '  MIGRATION SUMMARY' -ForegroundColor White
if ($DryRun) {
    Write-Host "  Would add  : $wouldAdd" -ForegroundColor Cyan
} else {
    Write-Host "  Added      : $added"    -ForegroundColor Green
}
Write-Host "  Skipped    : $skipped  (already members)"  -ForegroundColor Gray
Write-Host "  Failed     : $failed"                      -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Gray' })
Write-Host "  Unresolved : $unresolved  (see CSV)"       -ForegroundColor $(if ($unresolved -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host '══════════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''