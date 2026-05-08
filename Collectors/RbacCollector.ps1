<#
.SYNOPSIS
    RbacCollector.ps1 — Collects Azure RBAC role assignments across all subscriptions.

.DESCRIPTION
    Uses Az modules only.
    Loops through every subscription the current identity can access.
    Collects all role assignments and records where they are applied.

    Output:
        RoleAssignments         — All assignments in one flat list
        SubscriptionsEnumerated — Subscriptions that were scanned
        CollectedAt             — When the scan ran (UTC)

.NOTES
    Requires: Az.Accounts, Az.Resources
#>

# Requires -Modules Az.Accounts, Az.Resources

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Logs non-fatal errors to CSV (if a log path is provided).
# If no path is provided, errors are ignored.
# ---------------------------------------------------------------------------

function Write-RbacCollectionError {
    param([string]$Source, [string]$Detail, [string]$LogPath)

    if (-not $LogPath) { return }

    [PSCustomObject]@{
        Timestamp = [datetime]::UtcNow.ToString('o')
        Source    = $Source
        Detail    = $Detail
    } | Export-Csv -LiteralPath $LogPath -Append -NoTypeInformation -Encoding UTF8
}

# ---------------------------------------------------------------------------
# Figures out what level a role assignment applies to.
#   Subscription level
#   Resource Group level
#   Individual resource level
#   Management Group level
# ---------------------------------------------------------------------------

function Resolve-RbacScopeType {
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Scope)

    # If it starts with Microsoft.Management → Management Group
    if ($Scope -match '^/providers/Microsoft\.Management') { return 'ManagementGroup' }

    $parts = $Scope.TrimStart('/').Split('/')

    # /subscriptions/{id}
    if ($parts.Count -eq 2 -and $parts[0] -eq 'subscriptions') {
        return 'Subscription'
    }

    # /subscriptions/{id}/resourceGroups/{name}
    if ($parts.Count -eq 4 -and $parts[2] -eq 'resourcegroups') {
        return 'ResourceGroup'
    }

    # Anything deeper is a specific resource
    if ($parts.Count -gt 4) {
        return 'Resource'
    }

    return 'Unknown'
}

# ---------------------------------------------------------------------------
# Extracts the subscription ID from a scope string.
# ---------------------------------------------------------------------------

function Resolve-RbacSubscriptionId {
    [OutputType([string])]
    param([string] $Scope)

    if ($Scope -match '/subscriptions/([^/]+)') {
        return $Matches[1]
    }

    return ''
}

# ---------------------------------------------------------------------------
# Gets all role assignments inside ONE subscription.
# Converts raw Az output into a clean, consistent format.
# ---------------------------------------------------------------------------

function Get-SubscriptionRoleAssignments {
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory)] [string] $SubscriptionId,
        [string] $ErrorLogPath = ''
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        # Get all RBAC assignments at subscription scope
        $raw = Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId" -ErrorAction Stop

        foreach ($ra in $raw) {

            # Determine what level the role applies at
            $scopeType = Resolve-RbacScopeType -Scope $ra.Scope

            # Stores only the fields the engine needs
            $results.Add([PSCustomObject]@{
                PrincipalId        = $ra.ObjectId
                PrincipalName      = $ra.DisplayName
                PrincipalType      = $ra.ObjectType   # User | Group | ServicePrincipal
                RoleDefinitionName = $ra.RoleDefinitionName
                RoleDefinitionId   = $ra.RoleDefinitionId
                Scope              = $ra.Scope
                ScopeType          = $scopeType
                SubscriptionId     = $SubscriptionId

                # If assigned directly to a user → Direct
                # If via group/SP → Inherited
                AssignmentType     = if ($ra.ObjectType -eq 'User') { 'Direct' } else { 'Inherited' }
            })
        }
    }
    catch {
        Write-Debug "Failed to collect RBAC for subscription '$SubscriptionId': $_"

        Write-RbacCollectionError `
            -Source 'Get-SubscriptionRoleAssignments' `
            -Detail "SubscriptionId=$SubscriptionId | $($_.Exception.Message)" `
            -LogPath $ErrorLogPath
    }

    return $results
}

# ---------------------------------------------------------------------------
# MAIN FUNCTION
# Collects RBAC across ALL accessible subscriptions.
# ---------------------------------------------------------------------------

function Get-RbacSnapshot {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()] [string]   $ErrorLogPath       = '',
        [Parameter()] [string[]] $SubscriptionFilter = @()
    )

    $allAssignments = [System.Collections.Generic.List[PSCustomObject]]::new()
    $subsEnumerated = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Gets all subscriptions the current identity can access
    try {
        $subscriptions = Get-AzSubscription -ErrorAction Stop
    }
    catch {
        Write-Debug "Could not list subscriptions: $_"

        Write-RbacCollectionError `
            -Source 'Get-RbacSnapshot' `
            -Detail "Subscription enumeration failed: $($_.Exception.Message)" `
            -LogPath $ErrorLogPath

        # Return empty result if subscription lookup fails
        return [PSCustomObject]@{
            RoleAssignments         = $allAssignments
            SubscriptionsEnumerated = $subsEnumerated
            CollectedAt             = [datetime]::UtcNow
        }
    }

    # Only scan specific subscriptions if provided : this is optional 
    if ($SubscriptionFilter.Count -gt 0) {
        $subscriptions = $subscriptions |
            Where-Object { $SubscriptionFilter -contains $_.Id }
    }

    # Loops through each subscription
    foreach ($sub in $subscriptions) {

        Write-Debug "Scanning subscription '$($sub.Name)' ($($sub.Id))"

        # this keeps scanned records 
        $subsEnumerated.Add([PSCustomObject]@{
            SubscriptionId   = $sub.Id
            SubscriptionName = $sub.Name
            TenantId         = $sub.TenantId
            State            = $sub.State
        })

        # Collects the RBAC assignments for the current scanned subscription
        $assignments = Get-SubscriptionRoleAssignments `
            -SubscriptionId $sub.Id `
            -ErrorLogPath   $ErrorLogPath

        foreach ($a in $assignments) {
            $allAssignments.Add($a)
        }
    }

    # Returns everything in one structured object
    return [PSCustomObject]@{
        RoleAssignments         = $allAssignments
        SubscriptionsEnumerated = $subsEnumerated
        CollectedAt             = [datetime]::UtcNow
    }
}