# Identity Governance Validation Engine — Developer Reference

Four questions this document answers: how do you configure it, how do you run it, how do you extend it, and how do you integrate with it. For design rationale and the architecture behind these mechanics, see `ARCHITECTURE.md`. For the project overview, see `README.md`.

---

## Configure

### Permissions required

**Online mode:**

| Scope | Purpose |
|---|---|
| `User.Read.All` | Fetch user objects and attributes |
| `Group.Read.All` | Fetch group objects and membership |
| `Directory.Read.All` | Fetch role assignments and directory objects |
| `RoleManagement.Read.All` | Read Entra role definitions and assignments |
| `AuditLog.Read.All` | LastSignInDateTime |
| `PrivilegedAccess.ReadWrite.AzureADGroup` | PIM group eligibility |
| `PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup` | PIM eligibility schedule requests |

`onPremisesSyncEnabled` for both users and groups is covered by `User.Read.All` and `Group.Read.All`. No additional scope is required for hybrid identity detection.

**Offline mode** needs none of the above on your side. The customer runs `Export-TenantSnapshot.ps1` with delegated `User.Read.All`, `Group.Read.All`, and `Directory.Read.All`, consented to the first-party Microsoft Graph PowerShell SDK app at sign-in. Read-only; Global Reader is sufficient.

### Policy files

The engine reads two JSON documents at runtime, neither hardcoded:

- **`Rules.json`** — the entitlement model and every evaluated rule. Path defaults to `.\Rules.json`, overridden per run with `-RulesPath`.
- **`sod_policies.json`** — Separation of Duties conflict pairs. Always resolved relative to whichever `Rules.json` was loaded, so an engagement folder with its own `Rules.json` automatically gets its own `sod_policies.json` alongside it, with no path wiring required.

For a standalone deployment, both files live at the engine root. For a consulting engagement, both live inside that customer's folder under `Engagements/<Customer>/`, alongside their input CSVs and output reports. Switching between tenants or engagements is a `-RulesPath` argument, never a code change.

### Local auth setup

`profile.ps1` handles startup authentication for the Azure Function host: Managed Identity in deployed environments, client secret locally via `local.settings.json` (gitignored). For standalone interactive runs, authenticate directly with `Connect-MgGraph` — see Run, below.

---

## Run

### Commands

```powershell
# Online — connect interactively for standalone runs
Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Directory.Read.All","RoleManagement.Read.All"

# Online FullScan with SoD detection
.\ValidationEngine.ps1 -Mode FullScan -ExportJson -ExportCsv -StoreDriftState -Verbose

# Online DriftOnly — architecture, RBAC, and correlation findings only
.\ValidationEngine.ps1 -Mode DriftOnly -ExportJson -Verbose

# Offline FullScan against an engagement folder — no Graph connection needed
.\ValidationEngine.ps1 `
    -Mode       FullScan `
    -InputMode  offline `
    -UsersPath   .\Engagements\AcmeCorp\input\users.csv `
    -GroupsPath  .\Engagements\AcmeCorp\input\groups.csv `
    -MembersPath .\Engagements\AcmeCorp\input\group_members.csv `
    -RulesPath   .\Engagements\AcmeCorp\Rules.json `
    -OutputDir   .\Engagements\AcmeCorp\reports `
    -ExportJson -ExportCsv

# Local Azure Functions host — only needed for JML integration (PreProvision / PostProvision over HTTP)
func start
# JML engine calls POST /api/validate against this host automatically
```

`FullScan` and `DriftOnly` are always direct PowerShell invocations, run manually or wired into whatever scheduler you use externally (Task Scheduler, cron, an Azure Automation runbook). There is no Azure Functions timer trigger anywhere in this engine; `func start` exists solely to serve the `ValidateIdentity` HTTP endpoint the JML pipeline calls, and has nothing to do with how a FullScan gets kicked off.

### Scan mode reference

| Mode | Scope | Collection path | SoD evaluation |
|---|---|---|---|
| FullScan (online) | All identities, all rules | `Get-IdentitySnapshot` (full tenant) | Yes, against real `memberOf` |
| FullScan (offline) | All identities, identity-plane rules | `New-IdentitySnapshotFromCsv` (CSV, zero Graph calls) | Yes, against CSV membership |
| PreProvision (payload) | Single identity, blocking rules | `New-IdentitySnapshotFromPayload` (zero Graph calls) | No — no real memberships yet |
| PreProvision (targetUserId) | Single real identity | `Get-UserSnapshot` (3 Graph calls) | Yes, against actual tenant state |
| DriftOnly | Architecture, RBAC, Correlation | `Get-IdentitySnapshot` (full tenant) | Configurable |

Offline currently supports FullScan only.

### The three offline CSVs

| File | Columns | Maps to |
|---|---|---|
| `users.csv` | UserId, UserPrincipalName, DisplayName, AccountEnabled, JobTitle, Department, EmployeeType, EmployeeId, CreatedDateTime, UserType, OnPremisesSynced | User objects in the snapshot |
| `groups.csv` | GroupId, DisplayName, IsAssignableToRole, Description, OnPremisesSynced | Group objects, privilege derived the same way as online |
| `group_members.csv` | GroupId, UserId | The membership map (one row per membership) |

`Scripts/Export-TenantSnapshot.ps1` produces all three. The customer runs it once with `Connect-MgGraph` and their own Global Reader credentials, using the first-party Microsoft Graph PowerShell SDK app, so consent is to Microsoft, not a third party, and `Disconnect-MgGraph` clears the session at the end.

---

## Extend

### Repository structure

```
Validation_engine/
├── host.json
├── local.settings.json               # Gitignored
├── profile.ps1                       # Startup auth - Managed Identity or client secret
├── ValidationEngine.ps1              # Entry point · online/offline branch · enrichment map
├── Rules.json                        # Your tenant's entitlement model · 33 governance rules
├── sod_policies.json                 # Your tenant's SoD conflict pairs
├── ValidateIdentity/
│   ├── function.json                 # HTTP trigger binding
│   └── run.ps1                       # HTTP wrapper · mode routing · HYG-* demotion
├── Collectors/
│   ├── IDCollector.ps1               # Get-IdentitySnapshot · Get-UserSnapshot · New-IdentitySnapshotFromPayload · New-IdentitySnapshotFromCsv
│   └── RbacCollector.ps1
├── Rules/
│   ├── FindingSchema.ps1             # New-ComplianceFinding · Invoke-SuppressionPass
│   ├── IDRuleProcessor.ps1           # Identity · Access · Architecture · Hygiene · SoD
│   ├── RbacRuleProcessor.ps1
│   └── CorrelationRuleProcessor.ps1
├── Reporting/
│   ├── RiskClassifier.ps1
│   └── ReportGen.ps1                 # scanMode · rulesEvaluated · enrichment map in export
├── Scripts/
│   ├── Export-TenantSnapshot.ps1     # Customer-run export → the three offline CSVs
│   └── Migrate-LegacyGroups.ps1
├── Tests/
└── Engagements/                      # One self-contained folder per offline engagement
    └── <Customer>/
        ├── Rules.json                # Curated rule set agreed with this customer
        ├── sod_policies.json         # SoD pairs defined with this customer
        ├── input/                    # users.csv · groups.csv · group_members.csv
        └── reports/                  # Findings JSON and CSV
```

### Adding a new SoD conflict pair — data only, no code

The most common extension needs nothing but a JSON edit. Add an entry to `sod_policies.json`:

```json
{
  "id": "SOD-007",
  "name": "Vendor Onboarding / Vendor Payment Approval",
  "description": "The same identity should not both onboard vendors and approve their payments.",
  "risk_rating": "High",
  "mode": "AnyToAny",
  "set_a": ["<GroupId for vendor onboarding>"],
  "set_b": ["<GroupId for vendor payment approval>"],
  "action": "Warn",
  "compensating_control": "Flag for governance review. Requires Procurement Director sign-off."
}
```

`Evaluate-SoDConflict` picks this up automatically on the next run. No PowerShell file changes, no dispatch table registration, nothing to redeploy.

### Adding a new rule — the three-step process

A rule that needs a genuinely new check (not just a new SoD pair) touches three places.

**1. Define the rule in `Rules.json`:**

```json
{
  "id": "CORR-006",
  "description": "Service principal holds Owner at subscription scope",
  "category": "Correlation",
  "severity": "Critical",
  "weight": 100,
  "blocking": true,
  "type": "Evaluate-ServicePrincipalExposure",
  "parameters": {
    "principalType": "ServicePrincipal",
    "forbiddenRoles": ["Owner"],
    "forbiddenScopes": ["/subscriptions/"]
  },
  "suppressesOnMatch": []
}
```

**2. Add the evaluator function and register it in the relevant processor's dispatch table.** Every processor's `type` field maps to a function via a dispatch table; a new rule either reuses an existing evaluator (as `sod_policies.json` reuses `Evaluate-SoDConflict`, or as ACCESS-004 reuses `Evaluate-PrivilegeDrift` with a new parameter flag) or needs a new one:

```powershell
# In CorrelationRuleProcessor.ps1

function Evaluate-ServicePrincipalExposure {
    param(
        [Parameter(Mandatory)] [PSCustomObject] $Rule,
        [Parameter(Mandatory)] [PSCustomObject] $IdentitySnapshot,
        [Parameter(Mandatory)] [PSCustomObject] $RbacSnapshot,
        [Parameter(Mandatory)] [hashtable]      $RbacIndex,
        [Parameter()]          [PSCustomObject] $RulesDocument = $null
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $p = $Rule.parameters
    foreach ($assignment in $RbacSnapshot.RoleAssignments) {
        if ($assignment.PrincipalType -ne $p.principalType) { continue }
        if ($p.forbiddenRoles -notcontains $assignment.RoleDefinitionName) { continue }
        if ($assignment.ScopeType -ne 'Subscription') { continue }
        $findings.Add((New-ComplianceFinding `
            -EntityId $assignment.PrincipalId -EntityType 'ServicePrincipal' `
            -RuleId $Rule.id -Category $Rule.category -Severity $Rule.severity `
            -Weight $Rule.weight -Blocking $Rule.blocking `
            -Details "Service principal '$($assignment.PrincipalName)' holds '$($assignment.RoleDefinitionName)' at subscription scope."))
    }
    return $findings
}

$Script:CorrelationDispatch["Evaluate-ServicePrincipalExposure"] = {
    param($r, $identSnap, $rbacSnap, $rbacIndex, $doc)
    Evaluate-ServicePrincipalExposure -Rule $r -IdentitySnapshot $identSnap -RbacSnapshot $rbacSnap -RbacIndex $rbacIndex -RulesDocument $doc
}
```

**3. Add a test.** At minimum: one case confirming the rule fires on a violating entity, one confirming it stays silent on a compliant one, and a suppression case if `suppressesOnMatch` is set on this rule or on a rule this one should supersede.

No change to `ValidationEngine.ps1`, `RiskClassifier.ps1`, or `ReportGen.ps1` is required for either extension path. This is the practical proof of ADR-005 (single finding schema) and ADR-002 (policy as JSON): classification and reporting operate on the finding shape alone and have no idea a new rule category exists.

---

## Integrate

The `ValidateIdentity` Azure Function is the integration point for the JML pipeline. Online only; offline mode is a direct script invocation with no function app involved.

**PreProvision request** (before the identity exists in Entra):
```json
{
  "mode": "PreProvision",
  "payload": {
    "EmployeeId": "E501",
    "UPN": "claire.dubois@contoso.com",
    "DisplayName": "Claire Dubois",
    "Department": "Finance",
    "JobTitle": "Head of Finance",
    "StartDate": "2026-06-01",
    "EmploymentType": "Employee",
    "Action": "Joiner"
  }
}
```

**PostProvision request** (against the real provisioned object):
```json
{
  "mode": "PostProvision",
  "targetUserId": "entra-object-id"
}
```

**Response shape:**
```json
{
  "passed": true,
  "failures": [],
  "warnings": [
    {
      "ruleId": "HYG-004",
      "category": "Hygiene",
      "severity": "Critical",
      "details": "Privileged account has no MFA registration or MFA is not enforced."
    }
  ],
  "matchedRuleIds": ["HYG-004"]
}
```

**PostProvision response with an SoD warning:**
```json
{
  "passed": true,
  "failures": [],
  "warnings": [
    {
      "ruleId": "SOD-EVAL-001/SOD-004",
      "category": "SoD",
      "severity": "High",
      "details": "[SOD-004] Payment Approver / Finance Auditor - conflicting groups: SG_Finance_PaymentApprovers, SG_Finance_Auditors"
    }
  ],
  "matchedRuleIds": ["SOD-EVAL-001/SOD-004", "HYG-004"]
}
```

`PostProvision` is not a distinct engine mode internally. `run.ps1` maps it to `-Mode PreProvision -TargetUserId`, which fetches the real object and evaluates it. `HYG-*` findings are demoted to warnings in this path specifically, regardless of their blocking flag, because a freshly created account has never signed in and cannot have MFA registered yet.