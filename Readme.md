# Identity Governance Validation Engine

### Microsoft Entra ID · Azure Functions · PowerShell

---

## What This Is

The Identity Governance Validation Engine is a policy-driven governance engine for Microsoft Entra ID that validates identities, access, RBAC, and tenant governance against a configurable rule set.

It can run in three modes:

* **Preventive** — validate a Joiner or Mover before provisioning occurs.
* **Detective** — validate immediately after provisioning.
* **Assessment** — scan an entire tenant or an offline customer export for governance drift.

The engine separates **facts** (the current identity state) from **policy** (governance rules). Every evaluation produces deterministic findings, a risk assessment, and a compliance decision.

---

## Key Capabilities

* Preventive validation before provisioning
* Detective validation after provisioning
* Scheduled tenant-wide governance scans
* Live Microsoft Graph assessment
* Offline CSV assessment with no tenant connection
* Separation of Duties (SoD) detection
* Azure RBAC governance validation
* Hybrid identity governance checks
* Risk scoring and compliance classification
* Structured JSON reporting for automation and audit

---

## Architecture

```
Microsoft Graph      Azure ARM      HR/JML Engine      CSV Export
      |                  |                |                 |
      +------------------+----------------+-----------------+
                         |
                  Collection Layer
                 (fact collection only)
                         |
                 Identity Snapshots
                         |
                  Rule Evaluation
                         |
                     Findings
                         |
                 Risk Classification
                         |
                 Reports & Decisions
```

Each layer has a single responsibility.

* **Collection** gathers and normalizes identity data.
* **Rule Evaluation** applies governance policy.
* **Classification** calculates compliance and risk.
* **Output** produces structured reports and workflow decisions.

Collectors never evaluate rules, and rule processors never communicate directly with Microsoft Graph. This separation keeps the engine predictable, testable, and portable.

---

## What It Validates

The engine currently evaluates **33 governance rules** across seven categories.

| Category                 | Examples                                                           |
| ------------------------ | ------------------------------------------------------------------ |
| **Identity**             | Disabled privileged account, malformed UPN, missing HR record      |
| **Access**               | Incorrect group membership, terminated user retaining access       |
| **Architecture**         | Tier-0 governance violations, service account misuse               |
| **Hygiene**              | Orphaned accounts, stale sign-ins, privileged account without MFA  |
| **RBAC**                 | Direct Owner assignments, overly broad privilege scope             |
| **Correlation**          | Identity and Azure RBAC risks visible only when evaluated together |
| **Separation of Duties** | Conflicting business responsibilities assigned to one identity     |

Rules are defined entirely in JSON rather than code, allowing governance policy to change without redeploying the engine.

---

## What It Produces

Every execution generates three outputs.

### Findings

Each governance violation includes:

* Rule ID
* Category
* Severity
* Risk weight
* Blocking status
* Entity
* Human-readable explanation

For example:

```
Rule: SOD-004
Severity: High
Entity: user@contoso.com

Conflict:
Payment Approval
+
Payment Processing

Decision:
Block
```

---

### Risk Assessment

Each identity receives:

* Compliance Status
* Risk Level
* Risk Score
* Risk Density

Compliance determines workflow decisions.

Risk Level provides operational prioritization.

Keeping these separate prevents operational hygiene issues from incorrectly blocking legitimate identity changes.

---

### Workflow Decision

Preventive validation produces a single decision:

* Pass
* Fail

If blocking findings exist, provisioning never reaches Microsoft Graph.

---

## Online and Offline Modes

### Online

The engine connects directly to Microsoft Graph and Azure Resource Manager to perform:

* Tenant-wide governance assessments
* Preventive JML validation
* Post-provision verification

Online mode supports the complete rule set, including RBAC, MFA, PIM, and sign-in analysis.

---

### Offline

Offline mode was designed for consulting engagements where customers prefer not to grant tenant-wide application consent.

Instead, the customer exports:

* Users
* Groups
* Group Memberships

The assessment runs entirely against those files.

No application registration.

No consent flow.

Nothing remains deployed after the engagement.

Although offline mode cannot evaluate Azure RBAC, MFA, PIM, or sign-in activity, both online and offline assessments produce the same finding schema and reporting format.

---

## Configuration

Governance policy is completely externalized.

The engine contains no tenant-specific logic.

Configuration is provided through JSON documents defining:

* Governance rules
* Privileged groups
* Employment-type policy
* Blocking vs warning behavior
* Separation of Duties conflict pairs

Each customer or engagement can therefore use its own governance model without modifying engine code.

---

## Project Status

| Component                      | Status      |
| ------------------------------ | ----------- |
| Collection layer (online)      | Stable      |
| Collection layer (offline CSV) | Stable      |
| Rule engine                    | Stable      |
| Risk classification            | Stable      |
| Reporting                      | Stable      |
| Separation of Duties           | Complete    |
| Azure RBAC validation          | Complete    |
| Hybrid identity governance     | Complete    |
| JML Joiner integration         | Complete    |
| JML Mover integration          | Complete    |
| JML Leaver integration         | In Progress |

---

## Known Limitations

The engine is intentionally **read-only**. It detects governance issues but does not perform remediation, allowing approval workflows and audit processes to remain separate.

Offline assessments cannot evaluate Azure RBAC, MFA state, PIM eligibility, or sign-in history because these require live Microsoft Graph or Azure Resource Manager access.

Several implementation improvements remain on the roadmap, including structured RBAC suppression logic and recalibration of the risk-scoring model.

---



---

## Documentation

| Document            | Purpose                                                             |
| ------------------- | ------------------------------------------------------------------- |
| **README.md**       | Project overview and capabilities                                   |
| **ARCHITECTURE.md** | Design decisions, ADRs, layer boundaries, and engineering rationale |
| **DEVELOPER.md**    | Setup, HTTP API, Microsoft Graph permissions, and local development |

---

*Part of an Identity and Access Management engineering portfolio focused on Microsoft Entra ID, Azure, and Identity Governance.*