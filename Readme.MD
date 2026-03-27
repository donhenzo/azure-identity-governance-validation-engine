# Identity Governance Validation Engine

A continuous compliance validation engine for Microsoft Azure / Entra ID environments. Evaluates identities against a declarative rule set, classifies risk, and serves as the compliance gate in a JML (Joiner-Mover-Leaver) provisioning workflow.

---

## What It Does

Most governance frameworks are calendar-driven — you audit quarterly, remediate what the audit found, and move on. This engine rejects that model. It treats compliance as a **continuously evaluable property of an identity**, producing consistent, structured output against the same 26 rules on every run.

- Scans Entra ID users, group memberships, MFA state, and Azure RBAC assignments
- Classifies each identity with a binary compliance status and a 0–100 risk score
- Acts as a pre-provision and post-provision gate in the JML provisioning workflow
- Detects structural drift between scans without requiring a full evaluation

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

| Mode | Scope | Collection path | Output | Typical use |
|---|---|---|---|---|
| `FullScan` | All identities · all 26 rules | `Get-IdentitySnapshot` — full tenant | EntityRiskStates[] · RiskScore · Summary | Weekly baseline |
| `PreProvision` (payload) | Single identity · blocking rules only | `New-IdentitySnapshotFromPayload` — zero Graph calls | Decision: Pass \| Fail · Reasons[] | Before Entra object is created |
| `PreProvision` (targetUserId) | Single real identity · blocking rules | `Get-UserSnapshot` — 3 Graph calls, O(1) | Decision: Pass \| Fail · Reasons[] | After provisioning (PostProvision gate) |
| `DriftOnly` | Structural rules · RBAC · Correlation | `Get-IdentitySnapshot` — full tenant | Entities with drift findings only | Daily between FullScans |

### How PostProvision Works

PostProvision is not a separate `-Mode` value in the engine. The HTTP trigger in `run.ps1` maps an incoming `mode: PostProvision` request to `-Mode PreProvision -TargetUserId`. The engine fetches the real Entra object via `Get-UserSnapshot` (3 Graph calls, O(1)) and evaluates it against the same rule set as a standard PreProvision run. The difference is that the user already exists in the tenant, so the snapshot reflects actual provisioned state rather than a synthetic payload.

HYG-* findings (MFA state, inactivity, password age) are demoted to warnings in this path. These are operational signals that cannot be enforced at the point of provisioning — the account was created seconds ago and has never been signed into. They appear in the JML audit report as warnings and do not block the event from completing.

---

## Rule Categories

| Category | Rules | Blocking Rules |
|---|---|---|
| Identity | IDENT-001/002/003 · JOIN-001/002 | IDENT-001/002 · JOIN-001/002 |
| Access | ACCESS-001/002/003 · ENT-001/002/003 | ACCESS-002 · ENT-002 |
| Architecture | ARCH-001/002/003 | ARCH-001 |
| Hygiene | HYG-001/002/003/004 | HYG-004 (FullScan only — demoted to warning in PostProvision) |
| RBAC | RBAC-001/002/003 | RBAC-003 |
| Correlation | CORR-001/002/003/004/005 | CORR-001/002/003 |

**26 rules total · 12 blocking · 5 suppression chains declared in `Rules.json`**

A blocking rule sets `ComplianceStatus = Blocking` in FullScan and `Decision = Fail` in PreProvision. Suppression chains prevent double-counting when a more specific rule already captures the same condition (e.g. `RBAC-003` suppresses `RBAC-001` and `RBAC-002` for the same entity).

---

## Entitlement Model and Mapping Rules

`Rules.json` contains three distinct sections:

**`entitlementModel`** — defines every governed group with its allowed employment types, access tier, and privilege classification. The validation engine reads this to evaluate ENT-001, ENT-002, ENT-003, and all privilege-sensitive rules.

**`mappingRules`** — drives JML provisioning. Each rule matches a canonical job title and employment type from the HR payload and defines the exact groups the identity receives, including Entra ID Object IDs and inline `privileged` flags. The mapping resolver reads this section at provisioning time.

**`rules`** — the 26 governance rules evaluated by the processor layer on every scan.

### Privilege Classification

Privilege is resolved from **two sources in combination**, not tier alone:

- `_privilegedTiers` in the entitlement model — catches groups whose tier is `Manager` or `Manager/Staff`
- `privileged: true` on individual group entries — catches groups that are operationally sensitive regardless of tier

This means groups like `SG_Security_Core` (tier: `Base`) and `SG_Security_Engineer` (tier: `Base/Staff`) are correctly treated as privileged. `IDRuleProcessor` and `CorrelationRuleProcessor` both read the entitlement model flag directly — rules HYG-004, CORR-001, and CORR-004 are all affected by this classification.

The `privileged` flag on mapping rule group entries is the authoritative source for PreProvision correlation checks. It is declared inline with the group assignment so the two cannot drift apart.

---

## Risk Scoring

```
RiskScore = Min( RawWeightSum / 900 × 100, 100.0 )
```

- Rule weights range from 15 (Low) to 100 (Critical)
- Fixed cap of 900 ensures scores are cross-run comparable
- `RiskDensity = RiskScore ÷ ViolationCount` separates concentrated severity from broad surface area
- Hygiene signals are scored but **excluded from the compliance gate** — an inactive account is a real concern, not the same category of failure as a terminated employee with live group memberships

---

## JML Integration

The engine runs as a PowerShell Azure Function app. The Python JML engine calls it over HTTP — the two runtimes are fully decoupled at the HTTP boundary.

### HTTP Contract

**Endpoint:** `POST /api/validate`

**PreProvision request** (identity does not yet exist in Entra ID):
```json
{
  "mode": "PreProvision",
  "payload": {
    "EmployeeId": "E001",
    "UPN": "alice.smith@contoso.com",
    "DisplayName": "Alice Smith",
    "Department": "Engineering",
    "JobTitle": "Software Engineer",
    "StartDate": "2026-04-01",
    "EmploymentType": "Employee",
    "Action": "Joiner"
  }
}
```

**PostProvision request** (confirms provisioned state after Graph API calls complete):
```json
{
  "mode": "PostProvision",
  "targetUserId": "entra-object-id"
}
```

**Response (both modes):**
```json
{
  "passed": true,
  "failures": [],
  "warnings": [
    {
      "ruleId": "HYG-004",
      "category": "Hygiene",
      "severity": "High",
      "details": "Privileged account has no MFA registration or MFA is not enforced."
    }
  ],
  "matchedRuleIds": ["HYG-004"]
}
```

`passed: false` with a non-empty `failures` array blocks the JML event. The Python pipeline routes the record to the hold queue with the failure reasons written to the audit report, traceable back to the exact rule ID that fired.

`warnings` are written to the audit report and do not block the event.

### PreProvision — No Graph Calls

When called with a payload, the engine builds a synthetic identity snapshot from the canonical payload fields using `New-IdentitySnapshotFromPayload`. No Graph calls are made. Rules that have no meaning pre-creation (sign-in activity, MFA registration, password age) are suppressed via the `IsPayloadScan` flag carried on the snapshot.

### PostProvision — Three Graph Calls, O(1)

When called with a `targetUserId`, the engine uses `Get-UserSnapshot` which makes exactly three Graph calls regardless of tenant size: `Get-MgUser`, `Get-MgUserMemberOf`, and `Get-MgGroup` per membership. This replaces the previous approach of fetching all tenant users then filtering — which scaled as O(groups × members) and caused consistent timeout failures on tenants with more than a few dozen groups.

---

## Output Files

| File | Description |
|---|---|
| `FullScan_Report_*.json` | Complete EntityRiskStates[], Summary{}, run metadata |
| `FullScan_Report_*.csv` | 24 columns per finding, one row per entity × finding |
| `LastRun_DriftState.json` | Previous run state used for RiskTrend comparison |
| `CollectionErrors_*.csv` | Non-fatal API errors with timestamp, source, and detail |

---

## Prerequisites

- PowerShell 7+
- `Microsoft.Graph` PowerShell SDK (installed locally at `~/.local/share/powershell/Modules`)
- `Az.Accounts` · `Az.Resources` modules
- Entra ID app registration with Graph API scopes: `User.Read.All`, `Group.Read.All`, `Directory.Read.All`, `RoleManagement.Read.All`
- `AuditLog.Read.All` required for `LastSignInDateTime` — engine detects and flags absence

### Local Authentication

The Function app authenticates to Microsoft Graph at startup via `profile.ps1`. When running locally the engine uses a client secret credential loaded from `local.settings.json`. When deployed to Azure, Managed Identity replaces the credential entirely — `profile.ps1` detects the `IDENTITY_ENDPOINT` environment variable and routes accordingly.

```powershell
# Local — connect interactively for standalone runs
Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Directory.Read.All","RoleManagement.Read.All"

# Then call the engine directly
& ./ValidationEngine.ps1 -Mode FullScan -ExportJson -ExportCsv -StoreDriftState -Verbose
```

---

## Repository Structure

```
Validation_engine/
├── host.json                         # Function app config · 5 min timeout
├── local.settings.json               # Gitignored · credentials + storage connection
├── profile.ps1                       # Startup auth · Managed Identity (Azure) or client secret (local)
├── requirements.psd1                 # Az module dependency
├── ValidationEngine.ps1              # Entry point · -Mode · -TargetUserId · -IdentityPayload · switches
├── Rules.json                        # Entitlement model · mapping rules · governance rules (v3.0.0)
├── ValidateIdentity/
│   ├── function.json                 # HTTP trigger binding · POST /api/validate
│   └── run.ps1                       # HTTP wrapper · translates request to engine params · response contract
├── Collectors/
│   ├── IDCollector.ps1               # Get-IdentitySnapshot · Get-UserSnapshot · New-IdentitySnapshotFromPayload
│   └── RbacCollector.ps1
├── Rules/
│   ├── FindingSchema.ps1             # New-ComplianceFinding · Invoke-SuppressionPass
│   ├── IDRuleProcessor.ps1           # Reads privileged flag from entitlement model
│   ├── RbacRuleProcessor.ps1
│   └── CorrelationRuleProcessor.ps1  # Reads privileged flag from entitlement model
├── Reporting/
│   ├── RiskClassifier.ps1            # Classification · no API calls · no rule logic
│   └── ReportGenerator.ps1           # Output generation
└── Scripts/
    └── Migrate-LegacyGroups.ps1      # One-time remediation pass · legacy group → standardised group migration

```

---

## Known Limitations

- **Read-only** — the engine detects and reports. It does not remediate. Automated remediation handlers consuming the JSON output are the intended next layer.
- **Fixed scoring cap** — adding new rules without updating the 900 cap will compress existing scores. Cap derivation from the active rule set is a planned improvement.
- **FullScan collection scales as O(groups × members)** — `Get-IdentitySnapshot` fetches all users, all groups, and all group memberships sequentially. On large tenants this becomes slow. `Get-UserSnapshot` (used for PostProvision) solves the single-user case. Parallelisation of the full tenant scan is documented but not yet implemented.
- **Sequential subscription enumeration** — RBAC collection processes one subscription at a time. Parallelisation is documented but not yet implemented.
- **No PIM visibility** — eligible role assignments via Privileged Identity Management are not currently evaluated. This is addressed in Phase 2 of the JML build.
- **Legacy group migration in progress** — existing tenant members are being migrated from legacy groups to the standardised group structure. FullScan findings against legacy groups will reduce as migration completes.

---

## Status

| Component | State |
|---|---|
| Collection layer | ✅ Stable |
| Rule evaluation (26 rules) | ✅ Stable |
| Classification · all 3 modes | ✅ Stable |
| Output layer | ✅ Stable |
| Rules.json · entitlement model + mapping rules | ✅ Updated — v3.0.0 |
| Privilege flag read · IDRuleProcessor + CorrelationRuleProcessor | ✅ Updated |
| HTTP trigger · ValidateIdentity | ✅ Complete |
| PreProvision via payload · New-IdentitySnapshotFromPayload | ✅ Complete |
| PostProvision via Get-UserSnapshot · O(1) | ✅ Complete |
| Local Graph auth via profile.ps1 · client secret | ✅ Complete |
| HYG-* demotion in PostProvision path | ✅ Complete |
| PowerShell collection unwrapping fix · return ,$allFindings | ✅ Applied to all three processors |
| Legacy group migration · Migrate-LegacyGroups.ps1 | 🔧 In progress |
| JML Phase 1 Joiner | ✅ Complete |
| JML Phase 2 PIM Eligibility | 📋 Planned |
| JML Phase 3 Mover | 📋 Planned |
| JML Phase 4 Leaver | 📋 Planned |

---

*Part of an IAM engineering portfolio demonstrating identity governance architecture on the Microsoft Azure stack.*