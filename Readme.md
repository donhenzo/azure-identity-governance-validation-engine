# Eliminating Reactive Compliance with a Continuous Identity Governance Engine

### Identity Governance Validation Engine — Microsoft Entra ID · Azure Functions · PowerShell

---

## Executive Summary

Most governance frameworks treat compliance as a calendar event. You audit quarterly, remediate what the audit found, and move on until the next cycle. In that model, an incorrectly provisioned identity can exist for weeks before anyone knows.

This engine rejects that model. It treats compliance as a continuously evaluable property of an identity — producing consistent, structured output against the same 27 rules on every run. It operates as both a standalone governance scanner and as the pre- and post-provision validation gate in the JML identity lifecycle pipeline.

No identity is created without clearing a hard pre-provision gate. No provisioned identity is accepted without a post-provision verification pass against actual Entra ID state. Every finding is traceable to a named rule ID. Every decision is structured, queryable, and produced at the time of the event — not reconstructed retrospectively.

---

## The Business Problem

Identity governance failures in most enterprise environments share the same root cause: validation is reactive. Access is granted first, reviewed later. The gap between provisioning and audit is where risk lives.

Three failure modes repeat consistently:

**Provisioning without policy enforcement.** Group assignment is inconsistent. Two people with the same job title in different departments receive different access depending on who processed the request. There is no structured record of what policy drove the decision.

**Post-hoc compliance discovery.** Compliance scans run after identities are created. A Contractor in a Manager-tier group is a finding on the next quarterly report — not a block at the point of creation. By then the access exists, it has been used, and it has to be explained.

**No structured decision trail.** Audit logs capture events. They do not capture structured policy decisions. When a compliance officer asks why a specific identity has a specific group assignment, the answer requires manual reconstruction across tickets, scripts, and workflow logs.

---

## Why Existing Approaches Fail

**Periodic compliance scanning** identifies drift after it has existed for weeks. It does not prevent it. The incorrectly provisioned identity already exists. Remediation requires additional work, additional audit entries, and in some cases a formal incident record.

**Entra ID Lifecycle Workflows** is optimised for rapid deployment and operational orchestration. Decision logic is distributed across workflows, group rules, and role assignments. Complex attribute-based policy becomes fragmented and difficult to maintain at scale. Audit logs capture lifecycle events, not structured policy decisions.

**Manual access review processes** introduce structural inconsistency. Policy lives in the mind of the engineer processing the request. It cannot be tested, versioned, or queried programmatically.

---

## Positioning

This engine is not a replacement for identity platforms such as Microsoft Entra ID or enterprise governance suites like SailPoint IdentityIQ or Saviynt Identity Cloud.

It operates as a policy evaluation and enforcement layer. As a standalone tool it runs continuous compliance scans against any Entra ID tenant. As part of the JML pipeline it acts as a hard gate — provisioning cannot proceed without a passing pre-provision evaluation, and no provisioned identity is accepted without a post-provision verification.

---

## Solution Overview

The engine evaluates identities against a declarative rule set declared in `Rules.json`. Rules are organised into six categories covering identity hygiene, access policy, architecture, RBAC, and cross-plane correlation. Every finding is attributed to a named rule ID. Every decision is structured and returned in a consistent HTTP response contract.

The core design principle is **evaluate before acting, not after**. Pre-provision validation runs against a synthetic snapshot built from the canonical identity payload — zero Graph API calls, no Entra object created yet. Post-provision validation runs against the real provisioned object using a targeted three-call Graph path. Both are hard gates in the pipeline.

---

## Key Capabilities

**Pre-Provision Validation Gate**
Evaluates a canonical identity payload against 27 rules before any Entra ID object is created. Builds a synthetic snapshot via `New-IdentitySnapshotFromPayload` — no Graph calls, no side effects. ENT-004 blocks Contractor and Intern employment types from being provisioned into Manager-tier roles at the payload level.

**Post-Provision Verification**
Re-evaluates the provisioned identity against actual Entra ID state using `Get-UserSnapshot` — three Graph calls, O(1) regardless of tenant size. ENT-002 checks actual group memberships against the entitlement model's `allowedEmployment` policy. HYG-* findings are demoted to warnings in this path — operational hygiene signals cannot be enforced at the point of provisioning.

**Employment Type Enforcement**
ENT-004 fires at the pre-provision stage against the payload directly. ENT-002 fires at post-provision against actual group memberships. The `employeeType` attribute is written to the Entra user object by the JML engine at provisioning time, making post-provision entitlement evaluation reliable.

**Employment Type Vocabulary Alignment**
The entitlement model uses `Employee | Contractor | Intern` — the same canonical vocabulary as the JML engine. The normaliser in `IDRuleProcessor.ps1` accepts both `employee` and `full-time` and maps both to `Employee`, removing the vocabulary dependency between the two systems and allowing tenants in transition to function correctly.

**Privilege Classification — Two-Source Model**
A group is classified as privileged if its tier is `Manager` or `Manager/Staff`, or if its `privileged` flag is explicitly `true` in the entitlement model. The two-source model catches groups like `SG_Security_Core` (tier: `Base`, `privileged: true`) that a tier-only check would miss. Both `IDRuleProcessor.ps1` and `CorrelationRuleProcessor.ps1` read the entitlement model flag directly.

**PIM Eligibility Collection (Phase 2)**
`Get-UserSnapshot` fetches active PIM eligibility schedules for the provisioned user via `Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule`. The `PimSchedules` field is populated on the snapshot and evaluated by `PIM-001`. Requires Entra ID P2. Absence of the permission is detected gracefully — PIM evaluation is skipped without failing the run.

**Continuous FullScan**
Scans all users, all groups, and all RBAC assignments across all subscriptions. Classifies each identity with a binary compliance status and a 0–100 risk score. Produces JSON and CSV output. Stores drift state for trend comparison between runs.

**Structured HTTP Response Contract**
The engine runs as a PowerShell Azure Function app. The Python JML engine calls it over HTTP at `POST /api/validate`. The response contract is consistent across all modes: `passed`, `failures`, `warnings`, `matchedRuleIds`. A `passed: false` response routes the JML event to the hold queue. The two runtimes are fully decoupled at the HTTP boundary.

---

## IAM Principles Demonstrated

**Policy Before Access**
Provisioning is conditional on governance validation. The pre-provision gate is a hard block. No speculative provisioning followed by remediation.

**Least Privilege Enforcement**
ENT-004 and ENT-002 together enforce employment type constraints at both the payload and entitlement level. Contractors cannot hold Manager-tier group memberships. This is enforced structurally, not by process.

**Separation of Concerns**
Collection has no rule logic. Rule evaluation has no classification logic. Classification has no output logic. Each layer has a single responsibility and a defined output contract.

**Complete Auditability**
Every finding is attributed to a named rule ID. Every pre-provision and post-provision decision is returned in a structured response written to the immutable per-identity audit report.

**Zero Trust Alignment**
No identity is trusted by default. Every lifecycle event is evaluated against policy before access is granted. Pre-provision evaluation uses a synthetic snapshot — the decision is made before the identity exists.

---

## Architecture

```
Microsoft Graph API          Azure ARM API          HR System / JML Engine
  User · Group · RBAC          All Subscriptions      IdentityPayload (canonical)
       │                              │                      │
       └──────────────┬───────────────┘                      │
                      ▼                                      │
          ┌─────────────────────┐                            │
          │     Collection      │ ◄──────────────────────────┘
          │  IDCollector.ps1    │  fact-only · no rule logic
          │  RbacCollector.ps1  │  Get-IdentitySnapshot (FullScan)
          │                     │  Get-UserSnapshot (PostProvision, O(1))
          │                     │    └─ includes PimSchedules (P2)
          │                     │  New-IdentitySnapshotFromPayload (PreProvision)
          └────────┬────────────┘
                   │  IdentitySnapshot · RbacSnapshot
                   ▼
          ┌─────────────────────┐
          │   Rule Evaluation   │
          │  IDRuleProcessor    │  Identity · Access · Architecture · Hygiene
          │  RbacRuleProcessor  │  RBAC
          │  CorrelationRule    │  cross-plane (requires both snapshots)
          │  FindingSchema      │  shared schema · Invoke-SuppressionPass
          └────────┬────────────┘
                   │  Findings[]
                   ▼
          ┌─────────────────────┐
          │   Classification    │
          │  RiskClassifier     │  FullScan · PreProvision · DriftOnly
          └────────┬────────────┘
                   │  EntityRiskStates[] · Summary · Decision
                   ▼
          ┌─────────────────────┐
          │      Output         │
          │  ReportGenerator    │  JSON · CSV · Drift State · Console · Error Log
          └────────┬────────────┘
                   │
                   ▼
          ┌─────────────────────────────────────────────────────┐
          │  JML Integration — HTTP Trigger (ValidateIdentity)  │
          │                                                     │
          │  POST /api/validate                                 │
          │    mode: PreProvision  → payload validation gate    │
          │    mode: PostProvision → provisioned state check    │
          │                                                     │
          │  Response: { passed, failures, warnings,            │
          │              matchedRuleIds }                       │
          └─────────────────────────────────────────────────────┘
```

---

## Scan Modes

| Mode | Scope | Collection Path | Output | Typical Use |
|---|---|---|---|---|
| `FullScan` | All identities · all 27 rules | `Get-IdentitySnapshot` — full tenant | EntityRiskStates[] · RiskScore · Summary | Weekly baseline |
| `PreProvision` (payload) | Single identity · blocking rules only | `New-IdentitySnapshotFromPayload` — zero Graph calls | Decision: Pass \| Fail · Reasons[] | Before Entra object is created |
| `PreProvision` (targetUserId) | Single real identity · blocking rules | `Get-UserSnapshot` — 3 Graph calls, O(1) | Decision: Pass \| Fail · Reasons[] | After provisioning (PostProvision gate) |
| `DriftOnly` | Structural rules · RBAC · Correlation | `Get-IdentitySnapshot` — full tenant | Entities with drift findings only | Daily between FullScans |

### How PostProvision Works

PostProvision is not a separate `-Mode` value. The HTTP trigger maps `mode: PostProvision` to `-Mode PreProvision -TargetUserId`. The engine fetches the real Entra object via `Get-UserSnapshot` and evaluates it against the same rule set.

HYG-* findings are demoted to warnings in this path — the account was created seconds ago, has never been signed into, and cannot yet have MFA registered. They appear in the JML audit report as warnings and do not block the event from completing.

---

## Rule Categories

| Category | Rules | Blocking Rules |
|---|---|---|
| Identity | IDENT-001/002/003 · JOIN-001/002 | IDENT-001/002 · JOIN-001/002 |
| Access | ACCESS-001/002/003 · ENT-001/002/003/004 · PIM-001 | ACCESS-002 · ENT-002 · ENT-004 |
| Architecture | ARCH-001/002/003 | ARCH-001 |
| Hygiene | HYG-001/002/003/004 | HYG-004 (FullScan · demoted in PostProvision) |
| RBAC | RBAC-001/002/003 | RBAC-003 |
| Correlation | CORR-001/002/003/004/005 | CORR-001/002/003 |

**27 rules total · 12 blocking · 5 suppression chains declared in `Rules.json`**

**ENT-004** — Pre-provision payload check. Blocks Contractor and Intern types from Manager, Director, HOD, or Executive roles before any Entra object is created. Uses `IsPayloadScan` flag to ensure it only fires in pre-provision context.

**ENT-002** — Post-provision entitlement check. Evaluates actual group memberships against the entitlement model's `allowedEmployment` policy. Requires `employeeType` to be written to the Entra user object at provisioning time.

**PIM-001** — Post-provision PIM verification. Confirms PIM eligibility schedules are present after provisioning. Non-blocking — schedule propagation can lag 15-30 seconds. Requires Entra ID P2.

---

## Technical Deep Dive

### Entitlement Model and Rules Structure

`Rules.json` contains three distinct sections:

**`entitlementModel`** — defines every governed group with its allowed employment types, access tier, and `privileged` flag. The validation engine reads this to evaluate ENT-001, ENT-002, ENT-003, and all privilege-sensitive rules.

**`mappingRules`** — drives JML provisioning entitlement resolution. Each rule matches a canonical job title, department, and employment type and defines the exact groups the identity receives, including `pimGroups` entries for Phase 2 PIM eligibility assignments.

**`rules`** — the 27 governance rules evaluated by the processor layer on every scan.

### PostProvision Graph Efficiency

The original post-provision path used `Get-IdentitySnapshot` — full tenant collection scaling as O(groups × members). On tenants with 50+ groups this consistently exceeded timeout thresholds, causing PostProvision to silently pass rather than evaluate.

`Get-UserSnapshot` replaces this with three targeted Graph calls:
1. `GET /users/{id}` — fetch the provisioned user
2. `GET /users/{id}/memberOf` — fetch this user's group memberships directly
3. `GET /groups/{id}` per membership — resolve display names for entitlement model lookup

Runtime dropped from consistent timeouts to approximately 12 seconds end-to-end.

### HTTP Contract

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

### Risk Scoring

```
RiskScore = Min( RawWeightSum / 900 × 100, 100.0 )
```

Rule weights range from 15 (Low) to 100 (Critical). The fixed cap of 900 ensures scores are cross-run comparable. `RiskDensity = RiskScore ÷ ViolationCount` separates concentrated severity from broad surface area.

---

## JML Integration — Phase Status

| Phase | JML Capability | Validation Engine Role | Status |
|---|---|---|---|
| Phase 0 | Data contracts · normalisation · event store | Architecture established | ✅ Complete |
| Phase 1 | Joiner provisioning pipeline | PreProvision gate · PostProvision gate · ENT-004 · ENT-002 | ✅ Complete |
| Phase 2 | PIM eligible role assignment | PIM-001 · PimSchedules in Get-UserSnapshot | ✅ Complete |
| Phase 3 | Mover — delta recalculation | Planned | 📋 Designed |
| HR API  | BambooHR ingestion · action derivation · delta polling | Validation engine called unchanged via HTTP | ✅ Complete |
| Phase 4 | Leaver — full revocation | Planned | 📋 Designed |

---

## Permissions Required

| Scope | Purpose |
|---|---|
| `User.Read.All` | Fetch user objects and attributes |
| `Group.Read.All` | Fetch group objects and membership |
| `Directory.Read.All` | Fetch role assignments and directory objects |
| `RoleManagement.Read.All` | Read Entra role definitions and assignments |
| `AuditLog.Read.All` | `LastSignInDateTime` — engine detects and flags absence |
| `PrivilegedAccess.ReadWrite.AzureADGroup` | PIM group eligibility assignment (Phase 2) |
| `PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup` | PIM eligibility schedule requests (Phase 2) |

---

## Running Locally

```powershell
# Connect interactively for standalone runs
Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Directory.Read.All","RoleManagement.Read.All"

# FullScan with all output formats
.\ValidationEngine.ps1 -Mode FullScan -ExportJson -ExportCsv -StoreDriftState -Verbose

# As part of JML pipeline — start the HTTP trigger
func start
# JML engine calls POST /api/validate automatically
# Works identically whether the JML engine ingests via CSV or BambooHR API
```

**The validation engine has no knowledge of the HR source.** It receives a canonical `IdentityPayload` or an Entra object ID via HTTP and evaluates it. Whether that payload originated from a CSV row or a BambooHR API call makes no difference to the engine — the HTTP contract is the boundary.

---

## Repository Structure

```
Validation_engine/
├── host.json                         # Function app config · 5 min timeout
├── local.settings.json               # Gitignored · credentials + storage connection
├── profile.ps1                       # Startup auth · Managed Identity or client secret
├── ValidationEngine.ps1              # Entry point · orchestrates all layers
├── Rules.json                        # Entitlement model · mapping rules · 27 governance rules
├── ValidateIdentity/
│   ├── function.json                 # HTTP trigger binding · POST /api/validate
│   └── run.ps1                       # HTTP wrapper · mode routing · HYG-* demotion in PostProvision
├── Collectors/
│   ├── IDCollector.ps1               # Get-IdentitySnapshot · Get-UserSnapshot (PimSchedules) · New-IdentitySnapshotFromPayload
│   └── RbacCollector.ps1             # Azure ARM RBAC collection across all subscriptions
├── Rules/
│   ├── FindingSchema.ps1             # New-ComplianceFinding · Invoke-SuppressionPass
│   ├── IDRuleProcessor.ps1           # ENT-004 · ENT-002 · PIM-001 · privilege flag · employment type normaliser
│   ├── RbacRuleProcessor.ps1         # RBAC-001/002/003
│   └── CorrelationRuleProcessor.ps1  # CORR-001/002/003/004/005 · privilege flag read
├── Reporting/
│   ├── RiskClassifier.ps1            # Risk scoring · compliance status · no API calls
│   └── ReportGenerator.ps1           # JSON · CSV · drift state · console output
└── Scripts/
    └── Migrate-LegacyGroups.ps1      # One-time remediation · legacy → standardised group migration
                                      # Employment-type-aware routing · DryRun · unresolved CSV export
```

---

## Limitations and Trade-offs

**Read-only.** The engine detects and reports. It does not remediate. Automated remediation handlers consuming the JSON output are the intended next layer.

**FullScan scales as O(groups × members).** `Get-IdentitySnapshot` fetches all users, all groups, and all memberships sequentially. On large tenants this becomes slow. `Get-UserSnapshot` solves the single-user case. Full tenant scan parallelisation is documented but not yet implemented.

**PIM eligibility requires Entra ID P2.** The PIM schedule cmdlets and eligibility schedule request endpoint both require P2. The engine detects absence gracefully — PIM evaluation is skipped rather than failing the run.

**PIM schedule propagation lag.** PIM eligibility assignments can take 15-30 seconds to appear in Graph after creation. PIM-001 is non-blocking for this reason. FullScan will catch persistent gaps.

**Fixed scoring cap.** Adding new rules without updating the 900 cap will compress existing scores. Cap derivation from the active rule set is a planned improvement.

---

## Status

| Component | State |
|---|---|
| Collection layer | ✅ Stable |
| Rule evaluation (27 rules) | ✅ Stable |
| Classification · all 3 modes | ✅ Stable |
| Output layer | ✅ Stable |
| ENT-004 · pre-provision payload check | ✅ Complete |
| ENT-002 · post-provision entitlement check | ✅ Complete |
| Employment type vocabulary alignment | ✅ Complete |
| Two-source privilege classification | ✅ Complete |
| Get-UserSnapshot · O(1) · replaces O(groups × members) | ✅ Complete |
| HYG-* demotion in PostProvision | ✅ Complete |
| PowerShell unary comma fix · all three processors | ✅ Applied |
| HTTP trigger · ValidateIdentity | ✅ Complete |
| PreProvision via payload · New-IdentitySnapshotFromPayload | ✅ Complete |
| PIM-001 · PIM eligibility verification | ✅ Complete (Phase 2) |
| Get-UserSnapshot PimSchedules · graceful fallback | ✅ Complete (Phase 2) |
| Evaluate-PimEligibility function · IDRuleProcessor | ✅ Complete (Phase 2) |
| Migrate-LegacyGroups.ps1 · employment-type-aware | ✅ Complete |
| JML Phase 3 Mover support | 📋 Planned |
| JML Phase 4 Leaver support | 📋 Planned |

---

*Part of an IAM engineering portfolio demonstrating identity governance architecture on the Microsoft Azure stack.