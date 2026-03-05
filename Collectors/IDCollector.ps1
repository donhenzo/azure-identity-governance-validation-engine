<#
.SYNOPSIS
    IdentityCollector.ps1 — Collects identity data from Microsoft Graph.

.DESCRIPTION
    Identity only collector that calls micprsoft groah and builds a normalized identity snapshot
    for the governance rule

    Output:
        Users         — Normalized user objects
        Groups        — Groups with privilege flags
        MembershipMap — UserId -> GroupId[]
        CollectedAt   — UTC timestamp

.NOTES
    Requires: Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.SignIns
#>

Set-StrictMode -Version Latest



# Error logging helper (optional CSV output)

function Write-IdentityCollectionError {
    param([string]$Source, [string]$Detail, [string]$LogPath)

    if (-not $LogPath) { return }

    [PSCustomObject]@{
        Timestamp = [datetime]::UtcNow.ToString('o')
        Source    = $Source
        Detail    = $Detail
    } | Export-Csv -LiteralPath $LogPath -Append -NoTypeInformation -Encoding UTF8
}



# User Collection
# Retrieves users and converts them into the normalized engine format

function Get-IdentityUsers {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param()

    # properties retrieved from Graph
    $properties = @(
        'id','displayName','userPrincipalName','accountEnabled',
        'jobTitle','department','employeeType','employeeId',
        'createdDateTime','lastPasswordChangeDateTime',
        'onPremisesSyncEnabled',
        'assignedLicenses','mail','userType','externalUserState'
    )

    # Detect whether signInActivity is available (P1/P2 tenants only). 
    # this helps to not fail when the user is not a preumiuim user
    # fails gracfully and continues the scan. 
    $includeSignIn = $false

    try {
        $probe = Get-MgUser -Top 1 -Property 'id,signInActivity' -ErrorAction Stop
        if ($probe) { $includeSignIn = $true }
    }
    catch {
        Write-Debug "Get-IdentityUsers: signInActivity unavailable."
    }

    if ($includeSignIn) {
        $properties += 'signInActivity'
        Write-Debug "Get-IdentityUsers: signInActivity detected."
    }

    $users = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {

        # Pull all users with the selected property set
        $page = Get-MgUser -All -Property ($properties -join ',')

        foreach ($user in $page) {

            # Last sign-in only available if the tenant supports signInActivity
            $lastSignIn = if ($includeSignIn) { $user.SignInActivity?.LastSignInDateTime } else { $null } 

            # Normalize Graph user into engine schema
            $users.Add([PSCustomObject]@{
                UserId                     = $user.Id
                DisplayName                = $user.DisplayName.Trim()
                UserPrincipalName          = $user.UserPrincipalName
                AccountEnabled             = $user.AccountEnabled
                JobTitle                   = $user.JobTitle
                Department                 = $user.Department
                EmployeeType               = $user.EmployeeType
                EmployeeId                 = $user.EmployeeId
                CreatedDateTime            = $user.CreatedDateTime
                LastPasswordChangeDateTime = $user.LastPasswordChangeDateTime
                LastSignInDateTime         = $lastSignIn
                OnPremisesSynced           = $user.OnPremisesSyncEnabled -eq $true
                UserType                   = $user.UserType
                ExternalUserState          = $user.ExternalUserState
                AssignedLicenses           = @($user.AssignedLicenses)
                MfaRegistered              = $null
                EmploymentStatus           = $null
                IsPrivileged               = $false
            })
        }
    }
    catch {
        Write-Debug "Get-IdentityUsers: Graph call failed: $_"
    }

    return $users
}



# Group Collection
# Retrieves groups and classifies privileged groups

function Get-IdentityGroups {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [string[]] $PrivilegedGroupPatterns = @(),
        [string[]] $PrivilegedGroupNames    = @()
    )

    $properties = @(
        'id','displayName','description','groupTypes',
        'securityEnabled','mailEnabled','isAssignableToRole',
        'onPremisesSyncEnabled','membershipRule','membershipRuleProcessingState'
    )

    $groups = [System.Collections.Generic.List[PSCustomObject]]::new()
    $page   = Get-MgGroup -All -Property ($properties -join ',')

    foreach ($group in $page) {

        # Privilege detection sources:
        # 1. Role-assignable groups
        # 2. Explicit entitlement model names
        # 3. Regex pattern matches
        $exactMatch   = $PrivilegedGroupNames.Count -gt 0 -and ($PrivilegedGroupNames -contains $group.DisplayName)
        $patternMatch = $PrivilegedGroupPatterns.Count -gt 0 -and (
            $PrivilegedGroupPatterns | Where-Object { $group.DisplayName -match $_ }
        )

        $isPrivileged = ($group.IsAssignableToRole -eq $true) -or $exactMatch -or $patternMatch

        $groups.Add([PSCustomObject]@{
            GroupId            = $group.Id
            DisplayName        = $group.DisplayName.Trim()
            Description        = $group.Description
            SecurityEnabled    = $group.SecurityEnabled
            MailEnabled        = $group.MailEnabled
            IsAssignableToRole = $group.IsAssignableToRole -eq $true
            IsDynamic          = ($group.MembershipRuleProcessingState -eq 'On')
            OnPremisesSynced   = $group.OnPremisesSyncEnabled -eq $true
            IsPrivileged       = [bool]$isPrivileged
        })
    }

    return $groups
}


# Membership Index
# Builds a lookup table: UserId -> GroupId[]

function Get-IdentityMemberships {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.Generic.List[PSCustomObject]] $Groups,
        [string] $ErrorLogPath = ''
    )

    $map = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($group in $Groups) {
        try {
            $members = Get-MgGroupMember -GroupId $group.GroupId -All -Property 'id' -ErrorAction Stop

            foreach ($member in $members) {
                if (-not $map.ContainsKey($member.Id)) {
                    $map[$member.Id] = [System.Collections.Generic.List[string]]::new()
                }

                $map[$member.Id].Add($group.GroupId)
            }
        }
        catch {
            Write-Debug "Membership collection failed for '$($group.DisplayName)'"

            Write-IdentityCollectionError `
                -Source 'Get-IdentityMemberships' `
                -Detail "GroupId=$($group.GroupId) | $($_.Exception.Message)" `
                -LogPath $ErrorLogPath
        }
    }

    return $map
}



# Employment Status Normalization
# Converts raw directory attributes into simplified lifecycle states

function Resolve-EmploymentStatus {
    [OutputType([string])]
    param([Parameter(Mandatory)] [PSCustomObject] $User)

    if ($User.UserType -eq 'Guest') { return 'Guest' }

    $terminatedKeywords = @('Terminated','Offboarded','Left','Resigned','Leaver')

    if ($User.EmployeeType -and $terminatedKeywords -contains $User.EmployeeType) {
        return 'Terminated'
    }

    if (-not $User.EmployeeId -and -not $User.AccountEnabled) { return 'Offboarded' }
    if ($User.EmployeeId -and $User.AccountEnabled)           { return 'Active' }
    if ($User.EmployeeId -and -not $User.AccountEnabled)      { return 'Terminated' }

    return 'Unknown'
}



# MFA State Resolution (optional due to Graph cost)

function Resolve-MfaState {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $UserId,
        [string] $ErrorLogPath = ''
    )

    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $UserId -ErrorAction Stop

        # Any authentication method other than password counts as MFA capability
        $mfaMethods = $methods | Where-Object {
            $_.AdditionalProperties['@odata.type'] -notmatch 'passwordAuthenticationMethod'
        }

        return ($mfaMethods.Count -gt 0)
    }
    catch {
        Write-Debug "Resolve-MfaState failed for '$UserId'"

        Write-IdentityCollectionError `
            -Source 'Resolve-MfaState' `
            -Detail "UserId=$UserId | $($_.Exception.Message)" `
            -LogPath $ErrorLogPath

        return $false
    }
}



# Privilege Propagation
# Marks users as privileged if they belong to privileged groups
function Set-UserPrivilegeFlag {
    param(
        [System.Collections.Generic.List[PSCustomObject]] $Users,
        [System.Collections.Generic.List[PSCustomObject]] $Groups,
        [hashtable] $MembershipMap
    )

    $privGroupIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($g in $Groups) {
        if ($g.IsPrivileged) { [void]$privGroupIds.Add($g.GroupId) }
    }

    foreach ($user in $Users) {

        if (-not $MembershipMap.ContainsKey($user.UserId)) { continue }

        $user.IsPrivileged =
            $MembershipMap[$user.UserId] |
            Where-Object { $privGroupIds.Contains($_) } |
            Select-Object -First 1

        $user.IsPrivileged = [bool]$user.IsPrivileged
    }
}



# Snapshot Builder
# Public entry point used by the validation engine

function Get-IdentitySnapshot {

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()] [string]   $TargetUserId            = '',
        [Parameter()] [string[]] $PrivilegedGroupPatterns = @('Admin','Tier0','Tier1','Privileged','Manager'),
        [Parameter()] [string[]] $PrivilegedGroupNames    = @(),
        [Parameter()] [string]   $ErrorLogPath            = '',
        [Parameter()] [switch]   $ResolveMfa
    )

    # Empty snapshot fallback
    $emptySnapshot = {
        [PSCustomObject]@{
            Users         = [System.Collections.Generic.List[PSCustomObject]]::new()
            Groups        = [System.Collections.Generic.List[PSCustomObject]]::new()
            MembershipMap = @{}
            CollectedAt   = [datetime]::UtcNow
        }
    }

    # User collection
    $allUsers = Get-IdentityUsers

    if ($TargetUserId) {
        $allUsers = $allUsers | Where-Object { $_.UserId -eq $TargetUserId }
        if ($allUsers.Count -eq 0) { return & $emptySnapshot }
    }

    # Normalize employment lifecycle state
    foreach ($user in $allUsers) {
        $user.EmploymentStatus = Resolve-EmploymentStatus -User $user
    }

    # Optional MFA resolution
    if ($ResolveMfa) {
        foreach ($user in $allUsers) {
            $user.MfaRegistered = Resolve-MfaState -UserId $user.UserId -ErrorLogPath $ErrorLogPath
        }
    }

    # Group collection
    $allGroups = Get-IdentityGroups `
        -PrivilegedGroupPatterns $PrivilegedGroupPatterns `
        -PrivilegedGroupNames $PrivilegedGroupNames

    # Membership index
    $membershipMap = Get-IdentityMemberships -Groups $allGroups -ErrorLogPath $ErrorLogPath

    # Propagate privilege flags
    Set-UserPrivilegeFlag -Users $allUsers -Groups $allGroups -MembershipMap $membershipMap

    return [PSCustomObject]@{
        Users         = $allUsers
        Groups        = $allGroups
        MembershipMap = $membershipMap
        CollectedAt   = [datetime]::UtcNow
    }
}