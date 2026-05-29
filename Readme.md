# Identity Governance Validation Engine

### Microsoft Entra ID · Azure Functions · PowerShell

---

## What This Is

This is a PowerShell-based governance engine that evaluates identities in a Microsoft Entra ID tenant against a declarative rule set. It runs in three modes: as a pre-provision gate before a user is created, as a post-provision verification after provisioning completes, and as a scheduled FullScan across all tenant users.

It connects to the JML identity lifecycle engine over HTTP. The Python engine calls `POST /api/validate` at two points in the provisioning pipeline. The governance engine evaluates the payload or the provisioned object and returns a structured response. The two systems are decoupled at the HTTP boundary and can also run independently.

---

## What It Catches

**At pre-provision.** A Contractor being provisioned into a Manager-tier group. A missing manager association. A duplicate UPN. An employment type that conflicts with the requested role. All of these are evaluated against the canonical identity payload before the Graph API is called, using a synthetic snapshot with zero side effects.

**At post-provision.** Whether the provisioned user actually received the expected groups. Whether any group membership violates the entitlement model's employment type policy. Whether MFA is registered on privileged accounts. Separation of Duties conflicts in the real provisioned state.

**During FullScan.** All of the above across every user in the tenant, plus RBAC findings (direct role assignments, Owner assignments at subscription scope), cross-plane correlation (privileged group members with subscription-level RBAC roles), and SoD conflicts that entered the tenant through any means, including manual assignment or processes that bypassed the JML engine.

---

## Why This Exists

Periodic compliance scans identify drift after it has existed for weeks. By the time the scan runs, the access has been active, it has likely been used, and remediation means additional audit entries. The scan is not a control; it is a report of failures.

This engine is a control. Pre-provision evaluation runs before the user exists. Post-provision evaluation runs seconds after provisioning completes. FullScan runs on a schedule to catch anything that slipped in through manual assignment or a process outside the JML pipeline. The finding format is consistent across all three modes, so audit reports and compliance evidence look the same regardless of which path produced them.

---

## Scan Modes

| Mode | Scope | Collection path | SoD evaluation |
|---|---|---|---|
| FullScan | All identities, all rules | Get-IdentitySnapshot (full tenant) | Yes, against real memberOf |
| PreProvision (payload) | Single identity, blocking rules | New-IdentitySnapshotFromPayload (zero Graph calls) | No, no real memberships yet |
| PreProvision (targetUserId) | Single real identity | Get-UserSnapshot (3 Graph calls) | Yes, against actual tenant state |
| DriftOnly | Architecture, RBAC, Correlation | Get-IdentitySnapshot (full tenant) | Configurable |

PostProvision is not a separate mode value. The HTTP trigger maps `mode: PostProvision` to `-Mode PreProvision -TargetUserId`. The engine fetches the real provisioned object and evaluates it. HYG-* findings are demoted to warnings in this path because a freshly created account has never been signed into and cannot have MFA registered yet.

---

## Rule Categories

| Category | Rules | Blocking |
|---|---|---|
| Identity | IDENT-001/002/003, JOIN-001/002 | IDENT-001/002, JOIN-001/002 |
| Access | ACCESS-001/002/003, ENT-001/002/003/004, PIM-001 | ACCESS-002, ENT-002, ENT-004 |
| Architecture | ARCH-001/002/003 | ARCH-001 |
| Hygiene | HYG-001/002/003/004 | HYG-004 (demoted in PostProvision) |
| RBAC | RBAC-001/002/003 | RBAC-003 |
| Correlation | CORR-001/002/003/004/005 | CORR-001/002/003 |
| SoD | SOD-EVAL-001 | Block policies in sod_policies.json |

27 identity and governance rules. SoD conflict pairs live in `sod_policies.json` and require no code change to add or modify.

---

## Separation of Duties

`Evaluate-SoDConflict` in `IDRuleProcessor.ps1` loads `sod_policies.json` and evaluates each user's group memberships against every conflict pair. The intersection logic is ANY_TO_ANY: a violation fires if the user holds at least one group from set_a and at least one group from set_b simultaneously.

```powershell
$matchedA = @($policy.set_a | Where-Object { $userGroupIds.Contains($_) })
$matchedB = @($policy.set_b | Where-Object { $userGroupIds.Contains($_) })

if ($matchedA.Count -gt 0 -and $matchedB.Count -gt 0) { # violation }
```

`sod_policies.json` is the single source of truth for conflict definitions. The Python JML engine reads the same file for its preventive pre-provision check. The PowerShell engine reads it for the detective FullScan and post-provision checks. The policy definitions are not duplicated, only the four-line intersection logic.

Block policies produce `Critical` blocking findings. Warn policies produce `High` non-blocking findings. Each SoD finding carries the compound rule ID `SOD-EVAL-001/{policy_id}` so findings are traceable to both the rule that detected the conflict and the policy that defined it.

Payload scans skip SoD evaluation because there are no real group memberships to evaluate against.

---

## Architecture

```
Microsoft Graph API          Azure ARM API          HR System / JML Engine
  User · Group · RBAC          All Subscriptions      IdentityPayload (canonical)
       |                              |                      |
       +-----------------------------+                      |
                      |                                     |
          +-----------v-----------+                         |
          |     Collection        | <-----------------------+
          |  IDCollector.ps1      |  fact-only, no rule logic
          |  RbacCollector.ps1    |  Get-IdentitySnapshot (FullScan)
          |                       |  Get-UserSnapshot (PostProvision, O(1))
          |                       |  New-IdentitySnapshotFromPayload (PreProvision)
          +----------+------------+
                     |  IdentitySnapshot · RbacSnapshot
                     v
          +----------+------------+
          |   Rule Evaluation     |
          |  IDRuleProcessor      |  Identity · Access · Architecture · Hygiene · SoD
          |  RbacRuleProcessor    |  RBAC
          |  CorrelationRule      |  cross-plane (requires both snapshots)
          |  FindingSchema        |  shared schema · Invoke-SuppressionPass
          +----------+------------+
                     |  Findings[]
                     v
          +----------+------------+
          |   Classification      |
          |  RiskClassifier       |  FullScan · PreProvision · DriftOnly
          +----------+------------+
                     |  EntityRiskStates[] · Summary · Decision
                     v
          +----------+------------+
          |      Output           |
          |  ReportGenerator      |  JSON · CSV · Drift State · Console
          +----------+------------+
                     |
                     v
          +--------------------------------------------+
          |  JML Integration (ValidateIdentity)        |
          |  POST /api/validate                        |
          |    mode: PreProvision  - payload gate      |
          |    mode: PostProvision - state check       |
          |                                            |
          |  Response: { passed, failures, warnings,   |
          |              matchedRuleIds }              |
          +--------------------------------------------+
```

---

## HTTP Contract

**PreProvision request:**
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

**PostProvision request:**
```json
{
  "mode": "PostProvision",
  "targetUserId": "entra-object-id"
}
```

**Response:**
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

**PostProvision response with SoD warning:**
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

---

## Risk Scoring

```
RiskScore = Min( RawWeightSum / 900 x 100, 100.0 )
```

Rule weights range from 15 (Low) to 100 (Critical). SoD block violations carry weight 100. SoD warn violations carry weight 70, configurable in `Rules.json`. The 900 cap keeps scores comparable across runs. `RiskDensity = RiskScore / ViolationCount` distinguishes a single severe finding from a broad spread of lower-severity ones.

---

## Privilege Classification

A group is classified as privileged if its tier is `Manager` or `Manager/Staff` in the entitlement model, or if its `privileged` flag is explicitly `true`. The two-source model catches groups like `SG_Security_Core`, which has a `Base` tier but is operationally privileged. Both `IDRuleProcessor.ps1` and `CorrelationRuleProcessor.ps1` read the flag directly from the entitlement model.

---

## JML Integration Status

| Phase | JML capability | Validation engine role | Status |
|---|---|---|---|
| Phase 0 | Data contracts, normalisation | Architecture established | Complete |
| Phase 1 | Joiner provisioning | PreProvision gate, PostProvision gate, ENT-004, ENT-002 | Complete |
| Phase 2 | PIM eligible role assignment | PIM-001, PimSchedules in Get-UserSnapshot | Complete |
| Phase 2.5 | Separation of Duties | Evaluate-SoDConflict, FullScan + PostProvision | Complete |
| Phase 3 | Mover delta recalculation | Planned | Designed |
| Phase 4 | Leaver full revocation | Planned | Designed |

---

## Permissions Required

| Scope | Purpose |
|---|---|
| `User.Read.All` | Fetch user objects and attributes |
| `Group.Read.All` | Fetch group objects and membership |
| `Directory.Read.All` | Fetch role assignments and directory objects |
| `RoleManagement.Read.All` | Read Entra role definitions and assignments |
| `AuditLog.Read.All` | LastSignInDateTime |
| `PrivilegedAccess.ReadWrite.AzureADGroup` | PIM group eligibility (Phase 2) |
| `PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup` | PIM eligibility schedule requests (Phase 2) |

---

## Running Locally

```powershell
# Connect interactively for standalone runs
Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Directory.Read.All","RoleManagement.Read.All"

# FullScan with SoD detection
.\ValidationEngine.ps1 -Mode FullScan -ExportJson -ExportCsv -StoreDriftState -Verbose

# As part of JML pipeline
func start
# JML engine calls POST /api/validate automatically
```

---

## Repository Structure

```
Validation_engine/
├── host.json
├── local.settings.json               # Gitignored
├── profile.ps1                       # Startup auth - Managed Identity or client secret
├── ValidationEngine.ps1              # Entry point
├── Rules.json                        # Entitlement model · 27 governance rules
├── sod_policies.json                 # SoD conflict pairs - single source of truth
├── ValidateIdentity/
│   ├── function.json                 # HTTP trigger binding
│   └── run.ps1                       # HTTP wrapper · mode routing · HYG-* demotion
├── Collectors/
│   ├── IDCollector.ps1               # Get-IdentitySnapshot · Get-UserSnapshot · New-IdentitySnapshotFromPayload
│   └── RbacCollector.ps1
├── Rules/
│   ├── FindingSchema.ps1             # New-ComplianceFinding · Invoke-SuppressionPass
│   ├── IDRuleProcessor.ps1           # ENT-004 · ENT-002 · PIM-001 · Evaluate-SoDConflict
│   ├── RbacRuleProcessor.ps1
│   └── CorrelationRuleProcessor.ps1
├── Reporting/
│   ├── RiskClassifier.ps1
│   └── ReportGenerator.ps1
└── Scripts/
    └── Migrate-LegacyGroups.ps1
```

---

## Known Limitations

**Read-only.** The engine detects and reports. It does not remediate. Remediation handlers that consume the JSON output are the intended next layer.

**FullScan scales as O(groups x members).** `Get-IdentitySnapshot` fetches all users, groups, and memberships sequentially. `Get-UserSnapshot` solves this for single-user checks. Full tenant scan parallelisation is documented but not yet built.

**SoD intersection logic is duplicated across runtimes.** The ANY_TO_ANY check is four lines in PowerShell here and equivalent Python in `sod_checker.py`. Policy definitions are not duplicated, only the evaluation logic. If the mode model expands, both need updating. The long-term path is a Python timer function that calls `sod_checker.py` directly.

**PIM requires Entra ID P2.** PIM schedule cmdlets and eligibility schedule requests both require P2. The engine skips PIM evaluation rather than failing if the licence is absent.

**PIM schedule propagation lag.** PIM eligibility assignments can take 15-30 seconds to appear in Graph after creation. PIM-001 is non-blocking for this reason.

**Fixed scoring cap.** The 900 cap needs updating if new rules push the maximum possible weight above it. Cap derivation from the active rule set is a planned improvement.

---

## Status

| Component | State |
|---|---|
| Collection layer | Stable |
| Rule evaluation (27 rules + SoD) | Stable |
| Classification, all 3 modes | Stable |
| Output layer | Stable |
| ENT-004, pre-provision payload check | Complete |
| ENT-002, post-provision entitlement check | Complete |
| Employment type vocabulary alignment | Complete |
| Two-source privilege classification | Complete |
| Get-UserSnapshot O(1) | Complete |
| HYG-* demotion in PostProvision | Complete |
| PowerShell unary comma fix across all processors | Applied |
| HTTP trigger, ValidateIdentity | Complete |
| PreProvision via payload, New-IdentitySnapshotFromPayload | Complete |
| PIM-001, PIM eligibility verification | Complete (Phase 2) |
| Get-UserSnapshot PimSchedules with graceful fallback | Complete (Phase 2) |
| Evaluate-SoDConflict in IDRuleProcessor | Complete (Phase 2.5) |
| SOD-EVAL-001 pointer rule in Rules.json | Complete (Phase 2.5) |
| sod_policies.json, 6 conflict pairs | Complete (Phase 2.5) |
| SoD FullScan, detective control | Complete (Phase 2.5) |
| SoD PostProvision, second independent check | Complete (Phase 2.5) |
| Migrate-LegacyGroups.ps1 | Complete |
| Phase 3 Mover support | Planned |
| Phase 4 Leaver support | Planned |

---

*Part of an IAM engineering portfolio on the Microsoft Azure stack.*