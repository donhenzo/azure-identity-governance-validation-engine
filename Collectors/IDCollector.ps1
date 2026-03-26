<#
.SYNOPSIS
    IdentityCollector.ps1 — Collects identity data from Microsoft Graph.

.DESCRIPTION
    Graph-only collector.
    Builds a clean, normalized identity snapshot for the rule engine.

    Output:
        Users         — Normalized user objects
        Groups        — Groups with privilege flags
        MembershipMap — UserId -> GroupId[]
        CollectedAt   — UTC timestamp
        IsPayloadScan — True when snapshot was built from a JML identity payload
                        (pre-creation, no Entra object exists yet)

.NOTES
    Requires: Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.SignIns
#>

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Writes non-fatal Graph errors to CSV if a log path is provided.
# If no log path is set, errors are silently ignored.
# ---------------------------------------------------------------------------

function Write-IdentityCollectionError {
    param([string]$Source, [string]$Detail, [string]$LogPath)

    if (-not $LogPath) { return }

    [PSCustomObject]@{
        Timestamp = [datetime]::UtcNow.ToString('o')
        Source    = $Source
        Detail    = $Detail
    } | Export-Csv -LiteralPath $LogPath -Append -NoTypeInformation -Encoding UTF8
}

# ---------------------------------------------------------------------------
# Retrieves all users with only the fields needed by the engine.
# Avoids pulling unnecessary properties hence reducing API payload.
# ---------------------------------------------------------------------------

function Get-IdentityUsers {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param()

    # ---------------------------------------------------------------------------
    # Base properties — available on all Entra license tiers
    # ---------------------------------------------------------------------------
    $properties = @(
        'id','displayName','userPrincipalName','accountEnabled',
        'jobTitle','department','employeeType','employeeId',
        'createdDateTime','lastPasswordChangeDateTime',
        'onPremisesSyncEnabled',
        'assignedLicenses','mail','userType','externalUserState'
    )

    # ---------------------------------------------------------------------------
    # Capability detection — signInActivity requires Entra ID P1 or P2.
    # We probe for it with a single-user call before committing to the full scan.
    # If the probe succeeds, we include it for all users.
    # If it fails (403), we proceed without it and LastSignInDateTime stays null.
    # ---------------------------------------------------------------------------
    $includeSignIn = $false

    try {
        $probe = Get-MgUser -Top 1 -Property 'id,signInActivity' -ErrorAction Stop
        if ($probe) { $includeSignIn = $true }
    }
    catch {
        Write-Debug "Get-IdentityUsers: signInActivity probe failed — tenant may not have P1/P2 license. LastSignInDateTime will be null."
    }

    if ($includeSignIn) {
        $properties += 'signInActivity'
        Write-Debug "Get-IdentityUsers: signInActivity detected — LastSignInDateTime will be populated."
    }

    $users = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        # ---------------------------------------------------------------------------
        # NOTE — Entra ID P1 or P2 license required for advanced query parameters:
        # -ConsistencyLevel eventual and -CountVariable enable server-side filtering
        # and accurate counts but require a premium license.
        #
        # PREMIUM (P1/P2 required):
        # $page = Get-MgUser -All -Property ($properties -join ',') -ConsistencyLevel eventual -CountVariable ignored
        #
        # STANDARD (works on all license tiers):
        $page = Get-MgUser -All -Property ($properties -join ',')
        # ---------------------------------------------------------------------------

        foreach ($user in $page) {

            # Resolve LastSignInDateTime only if the license supports it
            $lastSignIn = if ($includeSignIn) { $user.SignInActivity?.LastSignInDateTime } else { $null }

            # Convert raw Graph user into a normalized engine format
            $users.Add([PSCustomObject]@{
                UserId                     = $user.Id
                DisplayName                = $user.DisplayName.Trim()  # Graph can return trailing whitespace
                UserPrincipalName          = $user.UserPrincipalName
                AccountEnabled             = $user.AccountEnabled
                JobTitle                   = $user.JobTitle
                Department                 = $user.Department
                EmployeeType               = $user.EmployeeType
                EmployeeId                 = $user.EmployeeId
                CreatedDateTime            = $user.CreatedDateTime
                LastPasswordChangeDateTime = $user.LastPasswordChangeDateTime
                LastSignInDateTime         = $lastSignIn  # null on non-premium tenants
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
        # User collection failed — return empty list so the snapshot can still
        # be built with groups and membership data rather than throwing entirely
        Write-Debug "Get-IdentityUsers: Graph call failed: $_"
    }

    return $users
}

# ---------------------------------------------------------------------------
# Retrieves all groups and marks which ones are considered privileged.
# A group is privileged if:
#   - It is role-assignable, OR
#   - Its name matches configured privilege patterns.
# ---------------------------------------------------------------------------

function Get-IdentityGroups {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        # Regex patterns for privilege detection — catches role-assignable groups
        # and any groups whose names match configured patterns.
        [string[]] $PrivilegedGroupPatterns = @(),
        # Exact group display names sourced from entitlementModel in Rules.json
        # whose tier is in _privilegedTiers. This is the authoritative source —
        # pattern matching alone misses groups like Exec_Team whose names don't
        # contain the tier string ('Manager').
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

        # A group is privileged if any of the following are true:
        #   1. It is role-assignable in Entra ID (authoritative Azure signal)
        #   2. Its display name exactly matches a group from the entitlement model
        #      whose tier is in _privilegedTiers (e.g. Exec_Team → Manager tier)
        #   3. Its display name matches a configured regex pattern (catch-all for
        #      groups not in the model, e.g. legacy Admin/Tier0 naming conventions)
        $exactMatch   = $PrivilegedGroupNames.Count -gt 0 -and ($PrivilegedGroupNames -contains $group.DisplayName)
        $patternMatch = $PrivilegedGroupPatterns.Count -gt 0 -and (
            $PrivilegedGroupPatterns | Where-Object { $group.DisplayName -match $_ }
        )
        $isPrivileged = ($group.IsAssignableToRole -eq $true) -or $exactMatch -or $patternMatch

        $groups.Add([PSCustomObject]@{
            GroupId            = $group.Id
            DisplayName        = $group.DisplayName.Trim()  # Graph can return trailing whitespace
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

# ---------------------------------------------------------------------------
# Builds a lookup table of UserId -> list of GroupIds.
# Errors for individual groups are logged but do not stop the process.
# ---------------------------------------------------------------------------

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
            Write-Debug "Get-IdentityMemberships failed for '$($group.DisplayName)': $_"

            Write-IdentityCollectionError `
                -Source 'Get-IdentityMemberships' `
                -Detail "GroupId=$($group.GroupId) | $($_.Exception.Message)" `
                -LogPath $ErrorLogPath
        }
    }

    return $map
}

# ---------------------------------------------------------------------------
# Converts raw HR / directory fields into simplified employment states.
# Rules rely on this normalized value, not raw attributes.
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Checks whether a user has any non-password authentication method registered.
# Optional due to performance and Graph throttling.
# ---------------------------------------------------------------------------

function Resolve-MfaState {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $UserId,
        [string] $ErrorLogPath = ''
    )

    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $UserId -ErrorAction Stop

        $mfaMethods = $methods | Where-Object {
            $_.AdditionalProperties['@odata.type'] -notmatch 'passwordAuthenticationMethod'
        }

        return ($mfaMethods.Count -gt 0)
    }
    catch {
        Write-Debug "Resolve-MfaState failed for '$UserId': $_"

        Write-IdentityCollectionError `
            -Source 'Resolve-MfaState' `
            -Detail "UserId=$UserId | $($_.Exception.Message)" `
            -LogPath $ErrorLogPath

        return $false
    }
}

# ---------------------------------------------------------------------------
# Marks users as privileged if they belong to any privileged group.
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Public entry point.
# Builds and returns a full identity snapshot for the engine.
# Supports optional single-user mode (PreProvision).
# ---------------------------------------------------------------------------

function Get-IdentitySnapshot {

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()] [string]   $TargetUserId           = '',
        [Parameter()] [string[]] $PrivilegedGroupPatterns = @('Admin','Tier0','Tier1','Privileged','Manager'),
        # Exact group display names from the entitlement model whose tier is privileged.
        # Passed from the engine, which reads them directly from Rules.json.
        [Parameter()] [string[]] $PrivilegedGroupNames    = @(),
        [Parameter()] [string]   $ErrorLogPath            = '',
        [Parameter()] [switch]   $ResolveMfa
    )

    $emptySnapshot = {
        [PSCustomObject]@{
            Users         = [System.Collections.Generic.List[PSCustomObject]]::new()
            Groups        = [System.Collections.Generic.List[PSCustomObject]]::new()
            MembershipMap = @{}
            CollectedAt   = [datetime]::UtcNow
            IsPayloadScan = $false
        }
    }

    # Get users (optionally filter to a single user)
    $allUsers = Get-IdentityUsers

    if ($TargetUserId) {
    # Wrap in @() — Where-Object returns a single object when one user matches,
    # which does not have a .Count property. @() forces array typing consistently.
    $allUsers = @($allUsers | Where-Object { $_.UserId -eq $TargetUserId })
    if ($allUsers.Count -eq 0) { return & $emptySnapshot }
}
    # Normalize employment status
    foreach ($user in $allUsers) {
        $user.EmploymentStatus = Resolve-EmploymentStatus -User $user
    }

    # Optionally resolve MFA state
    if ($ResolveMfa) {
        foreach ($user in $allUsers) {
            $user.MfaRegistered = Resolve-MfaState -UserId $user.UserId -ErrorLogPath $ErrorLogPath
        }
    }

    # Get groups and classify privilege
    $allGroups = Get-IdentityGroups -PrivilegedGroupPatterns $PrivilegedGroupPatterns -PrivilegedGroupNames $PrivilegedGroupNames

    # Build user -> group membership index
    $membershipMap = Get-IdentityMemberships -Groups $allGroups -ErrorLogPath $ErrorLogPath

    # Mark privileged users
    Set-UserPrivilegeFlag -Users $allUsers -Groups $allGroups -MembershipMap $membershipMap

    return [PSCustomObject]@{
        Users         = $allUsers
        Groups        = $allGroups
        MembershipMap = $membershipMap
        CollectedAt   = [datetime]::UtcNow
        IsPayloadScan = $false
    }
}

# ---------------------------------------------------------------------------
# New-IdentitySnapshotFromPayload
# Builds a synthetic identity snapshot from a JML canonical identity object.
# Used by the validation engine PreProvision path when the user does not yet
# exist in Entra ID — no Graph calls are made.
#
# Purpose:      Allow the validation engine to run PreProvision rules against
#               a JML payload before any Entra ID object is created.
# Input:        A canonical identity object produced by the JML normalization layer.
# Output:       A snapshot in the same shape as Get-IdentitySnapshot, with
#               IsPayloadScan = $true so processors can detect pre-creation context.
# Side effects: None — no Graph calls, no writes.
# Security:     UPN duplicate check must still be performed separately by the
#               JML engine via Graph before provisioning executes. This function
#               does not query Entra ID and cannot detect conflicts.
# ---------------------------------------------------------------------------

function New-IdentitySnapshotFromPayload {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        # The canonical identity object produced by the JML normalization layer.
        # Must conform to the canonical identity schema defined in the decision log.
        [Parameter(Mandatory)] [PSCustomObject] $Payload
    )

    # Validate minimum required fields before building the snapshot.
    # Missing fields would cause silent null comparisons in rule processors
    # rather than obvious failures — catch them here instead.
    $requiredFields = @('EmployeeId','UPN','DisplayName','Department','JobTitle','EmploymentType','Action')
    foreach ($field in $requiredFields) {
        if (-not $Payload.PSObject.Properties[$field] -or
            [string]::IsNullOrWhiteSpace($Payload.$field)) {
            throw "New-IdentitySnapshotFromPayload: Payload is missing required field '$field'."
        }
    }

    # Build a synthetic user object matching the shape Get-IdentitySnapshot returns.
    # Fields with no meaning pre-creation (sign-in, password age, licenses) are set
    # to null. Rules that evaluate these fields will not fire because IsPayloadScan
    # gates them at the processor level.
    $syntheticUser = [PSCustomObject]@{
        UserId                     = "PREPROVISION-$($Payload.EmployeeId)"  # Stable ID for finding correlation
        DisplayName                = $Payload.DisplayName
        UserPrincipalName          = $Payload.UPN
        AccountEnabled             = $false          # Does not exist in Entra yet
        JobTitle                   = $Payload.JobTitle
        Department                 = $Payload.Department
        EmployeeType               = $Payload.EmploymentType
        EmployeeId                 = $Payload.EmployeeId
        CreatedDateTime            = $null           # Not created yet
        LastPasswordChangeDateTime = $null           # No password history
        LastSignInDateTime         = $null           # No sign-in history
        OnPremisesSynced           = $false
        UserType                   = 'Member'        # Default for internal provisioning
        ExternalUserState          = $null
        AssignedLicenses           = @()             # No licenses assigned yet
        MfaRegistered              = $null           # Cannot check pre-creation
        EmploymentStatus           = 'Active'        # Normalization layer confirmed this before payload reached here
        IsPrivileged               = $false          # Not yet assigned to any group
    }

    # Groups and MembershipMap are empty — user has no memberships yet.
    # IsPayloadScan = $true signals to rule processors that hygiene and
    # sign-in based rules should not fire against this snapshot.
    return [PSCustomObject]@{
        Users         = [System.Collections.Generic.List[PSCustomObject]]@($syntheticUser)
        Groups        = [System.Collections.Generic.List[PSCustomObject]]::new()
        MembershipMap = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        CollectedAt   = [datetime]::UtcNow
        IsPayloadScan = $true
    }
}

# Get-UserSnapshot
# Lightweight targeted snapshot for PostProvision validation.
# Three Graph calls regardless of tenant size — O(1) runtime.
#
# Contrast with Get-IdentitySnapshot which fetches all users, all groups,
# and all memberships — O(groups × members). Correct for FullScan but
# too slow for single-user PostProvision checks.
function Get-UserSnapshot {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string] $UserId
    )

    # Call 1 — fetch the single user by object ID
    $user = Get-MgUser -UserId $UserId -Property (
        'id,displayName,userPrincipalName,accountEnabled,' +
        'jobTitle,department,employeeType,employeeId,' +
        'createdDateTime,lastPasswordChangeDateTime,' +
        'onPremisesSyncEnabled,assignedLicenses,' +
        'mail,userType,externalUserState'
    ) -ErrorAction Stop

    $userObj = [PSCustomObject]@{
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
        LastSignInDateTime         = $null
        OnPremisesSynced           = $user.OnPremisesSyncEnabled -eq $true
        UserType                   = $user.UserType
        ExternalUserState          = $user.ExternalUserState
        AssignedLicenses           = @($user.AssignedLicenses)
        MfaRegistered              = $null
        EmploymentStatus           = $null
        IsPrivileged               = $false
    }

    $userObj.EmploymentStatus = Resolve-EmploymentStatus -User $userObj

    # Call 2 — fetch only this user's group memberships directly
    $memberOf = Get-MgUserMemberOf -UserId $UserId -All -ErrorAction Stop
    $groupIds = @(
        $memberOf |
        Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' } |
        Select-Object -ExpandProperty Id
    )

    # Build a minimal group list from what the user is actually in
    $groupList = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($gid in $groupIds) {
        try {
            $g = Get-MgGroup -GroupId $gid `
                -Property 'id,displayName,isAssignableToRole,membershipRule' `
                -ErrorAction Stop
            $groupList.Add([PSCustomObject]@{
                GroupId            = $g.Id
                DisplayName        = $g.DisplayName.Trim()
                Description        = ''
                SecurityEnabled    = $true
                MailEnabled        = $false
                IsAssignableToRole = $g.IsAssignableToRole -eq $true
                IsDynamic          = ($null -ne $g.MembershipRule)
                OnPremisesSynced   = $false
                IsPrivileged       = $g.IsAssignableToRole -eq $true
            })
        }
        catch {
            Write-Debug "Get-UserSnapshot: could not fetch group $gid — $_"
        }
    }

    # Build membership map with just this user
    $membershipMap = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($groupIds.Count -gt 0) {
        $membershipMap[$UserId] = [System.Collections.Generic.List[string]]::new()
        foreach ($gid in $groupIds) { $membershipMap[$UserId].Add($gid) }
    }

    $userObj.IsPrivileged = @($groupList | Where-Object { $_.IsPrivileged }).Count -gt 0

    return [PSCustomObject]@{
        Users         = [System.Collections.Generic.List[PSCustomObject]]@($userObj)
        Groups        = $groupList
        MembershipMap = $membershipMap
        CollectedAt   = [datetime]::UtcNow
        IsPayloadScan = $false
    }
}