# Identity Governance Validation Engine

A continuous compliance validation engine for Microsoft Azure / Entra ID environments. Evaluates identities against a declarative rule set, classifies risk, and serves as the compliance gate in a JML (Joiner-Mover-Leaver) provisioning workflow.

---

## What It Does

Most governance frameworks are calendar-driven — you audit quarterly, remediate what the audit found, and move on. This engine rejects that model. It treats compliance as a **continuously evaluable property of an identity**, producing consistent, structured output against the same 26 rules on every run.

- Scans Entra ID users, group memberships, MFA state, and Azure RBAC assignments
- Classifies each identity with a binary compliance status and a 0–100 risk score
- Blocks non-compliant identities from being provisioned in the JML workflow
- Detects structural drift between scans without requiring a full evaluation

---

## Architecture

```
Microsoft Graph API          Azure ARM API          HR System (SCIM)
  User · Group · RBAC          All Subscriptions      EmployeeType · EmployeeId
       │                              │                      │
       └──────────────┬───────────────┘                      │
                      ▼                                       │
          ┌─────────────────────┐                            │
          │     Collection      │ ◄──────────────────────────┘
          │  IdentityCollector  │  fact-only · no rule logic
          │  RbacCollector      │
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
                   │  (in development)
                   ▼
          ┌─────────────────────┐
          │  JML Orchestration  │
          │  Joiner             │  HR trigger → PreProvision → Pass/Fail
          │  Mover              │  role change → revoke → re-evaluate
          │  Leaver             │  termination → disable → verify revocation
          └─────────────────────┘
```

---

## Scan Modes

| Mode | Scope | Output | Typical Schedule |
|---|---|---|---|
| `FullScan` | All identities · all 26 rules | EntityRiskStates[] · RiskScore · Summary | Weekly baseline |
| `PreProvision` | Single user · blocking rules only | Decision: Pass \| Fail · Reasons[] | On every JML event |
| `DriftOnly` | Structural rules · RBAC · Correlation | Entities with drift findings only | Daily between FullScans |

---

## Rule Categories

| Category | Rules | Blocking Rules |
|---|---|---|
| Identity | IDENT-001/002/003 · JOIN-001/002 | IDENT-001/002 · JOIN-001/002 |
| Access | ACCESS-001/002/003 · ENT-001/002/003 | ACCESS-002 · ENT-002 |
| Architecture | ARCH-001/002/003 | ARCH-001 |
| Hygiene | HYG-001/002/003/004 | HYG-004 |
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
- `Microsoft.Graph` PowerShell SDK
- `Az.Accounts` · `Az.Resources` modules
- Entra ID service principal with the Graph scopes listed above
- `AuditLog.Read.All` required for `LastSignInDateTime` — engine detects and flags absence

---

## Repository Structure

```
ValidationEngine/
├── ValidationEngine.ps1          # Entry point · -Mode · -TargetUserId · switches
├── Rules.json                    # Entitlement model · mapping rules · governance rules (v3.0.0)
├── Collectors/
│   ├── IdentityCollector.ps1
│   └── RbacCollector.ps1
├── Rules/
│   ├── FindingSchema.ps1         # New-ComplianceFinding · Invoke-SuppressionPass
│   ├── IDRuleProcessor.ps1       # Reads privileged flag from entitlement model
│   ├── RbacRuleProcessor.ps1
│   └── CorrelationRuleProcessor.ps1  # Reads privileged flag from entitlement model
├── Reporting/
│   ├── RiskClassifier.ps1        # Classification · no API calls · no rule logic
│   └── ReportGenerator.ps1       # Output generation
└── Tests/
    └── Test-*.ps1                # Unit tests per module
```

---

## Known Limitations

- **Read-only** — the engine detects and reports. It does not remediate. Automated remediation handlers consuming the JSON output are the intended next layer.
- **Fixed scoring cap** — adding new rules without updating the 900 cap will compress existing scores. Cap derivation from the active rule set is a planned improvement.
- **Sequential subscription enumeration** — RBAC collection processes one subscription at a time. Parallelisation is documented but not yet implemented.
- **No PIM visibility** — eligible role assignments via Privileged Identity Management are not currently evaluated.
- **New groups are currently empty** — the entitlement model has been updated to the standardised group structure. Existing tenant members are still in legacy groups pending migration in Phase 1 of the JML build. FullScan findings against the new group structure will not be meaningful until migration is complete.

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
| JML orchestration | 🔧 In development — Phase 1 Joiner next |

---

*Part of an IAM engineering portfolio demonstrating identity governance architecture on the Microsoft Azure stack.*