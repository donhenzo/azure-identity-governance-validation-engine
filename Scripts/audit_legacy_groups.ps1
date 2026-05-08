$legacyGroups = @(
    "Sales Team", "HR_Grp ",
    "ALLStaff ", "HR_Mangers",
    "Finance_Access", "Exec_Team",
    "Finance_Managers", "RBAC-admin",
    "Security_Eng_team ", "Engineering-Managers", "grp-az-prod-backend-read",
    "IT_Admins", "grp-az-helpdesk-contrib", "grp-az-helpdesk-read",
    "grp-az-dev-backend-contrib", "grp-az-dev-backend-read", "grp-az-accounting-read",
    "SalesManagers"
)

# Pull all groups once
$allGroups = Get-MgGroup -All -Property "id,displayName" -ErrorAction Stop

foreach ($name in $legacyGroups) {
    try {

        # Filter locally instead of querying Graph each time
        $group = $allGroups | Where-Object { $_.DisplayName -eq $name }

        if ($group) {

            # Accurate member count (handles paging correctly)
            $memberCount = (
                Get-MgGroupMember -GroupId $group.Id -All -ErrorAction Stop |
                Measure-Object
            ).Count

            Write-Host "$name — $memberCount members"
        }
        else {
            Write-Host "$name — not found"
        }

    }
    catch {
        Write-Host "$name — error retrieving members"
    }
}