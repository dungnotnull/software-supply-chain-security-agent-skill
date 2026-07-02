---
name: software-supply-chain-security__sub-hardening-roadmap
description: Sub-skill of software-supply-chain-security — Produce a prioritized, effort×impact hardening roadmap (pin/upgrade/sign/isolate) with the final scored deliverable, after the devil's-advocate pass.
---

## Purpose
Consume the scored reports and synthesize the final, open-source-ready deliverable: a scored report + a prioritized roadmap of concrete actions ranked by impact×effort, each with rationale, expected dimension delta, and citation. This is the only stage that emits the user-facing report.

## Inputs
- `InventoryRecord`, `VulnScanReport`, `ComplianceReport`, `ScoringReport`.
- Devil's-advocate objections (from `main.md` challenge stage) with resolutions.

## Action Catalog (the building blocks of the roadmap)

| Action class | Examples | Typical target dimension | Typical effort | Typical impact |
|--------------|----------|--------------------------|----------------|----------------|
| `pin` | Pin dep version / lockfile, pin action to SHA, pin base image to digest | D1, D3, D5 | low | medium |
| `upgrade` | Bump to fixed version; drop/replace abandoned dep | D1, D6 | low–med | high |
| `sign` | Adopt Sigstore/cosign signing; require signature policy | D4, D5 | med | high |
| `provenance` | Generate SLSA provenance; hermetic isolated build; reproducible build | D4 | med–high | high |
| `isolate` | Ephemeral runners, network isolation, private registry precedence, no mutable tags | D2, D5 | med | high |
| `policy` | Enforce 2FA/required reviews, license allowlist, max-CVSS gate | D3, D5 | low | medium |
| `replace` | Swap typosquat/abandoned/malicious dep for a trusted equivalent | D1, D2 | med | high |
| `monitor` | Enable OSV/EPSS continuous monitoring, weekly knowledge-brain refresh | D1, D6 | low | medium |

## Prioritization Model
For each candidate action compute:
```
impact_score  = Σ (weight[d] * expected_delta[d])        # reuse scoring weights
effort_score  = 1|2|3|4|5 (S/M/L/XL, person-days proxy)
priority      = impact_score / effort_score              # higher = do first
risk_if_skip  = HIGH|MEDIUM|LOW  (from priority_band of the finding it addresses)
```
Sort descending by `priority`; within tie, sort by `risk_if_skip` (HIGH first) then by lower effort. Assign a sequencing layer:
- **Wave 0 (do now, ≤1 day)**: low-effort, high-risk-reducing (pin criticals, upgrade fixable critical CVEs, remove known malicious).
- **Wave 1 (this sprint)**: high priority ratio items.
- **Wave 2 (next sprint)**: medium ratio, provenance/signing rollout.
- **Wave 3 (roadmap)**: SLSA L3→L4, reproducible builds, continuous monitoring.

## Procedure
1. **Generate candidate actions** from: every HIGH-priority finding (upgrade/replace), every license blocker (resolve/replace), every pipeline violation (pin/isolate/policy), SLSA gap to `required_slsa_level` (provenance/sign), every typosquat flag ≥0.5 (replace/review), every abandoned critical dep (replace).
2. **Compute impact/effort/priority** per candidate using the model above. Expected dimension delta is an estimate with rationale (cite which framework control it satisfies, e.g. "satisfies CICD-SEC-03").
3. **Resolve conflicts & dependencies**: e.g. `upgrade` may supersede `pin`; `provenance` requires `sign` first; collapse redundant actions.
4. **Fold in devil's-advocate resolutions**: any objection that changed a score or removed a false-positive action is recorded; any action reinstated after challenge carries the challenge note.
5. **Build the roadmap table** (see Output Schema) and the **final report** in the documented Output Format.
6. **Re-verify gates**: re-check that every dimension still cites evidence/assumption, compliance status is reflected, disclaimer present.

## Roadmap Table Schema
```yaml
Roadmap:
  waves:
    - wave: 0
      actions:
        - id: A-001
          title: str
          action_class: pin|upgrade|sign|provenance|isolate|policy|replace|monitor
          targets: [dependency_id | job | base_image]
          impact_score: float
          effort_score: int
          priority: float
          risk_if_skip: HIGH|MEDIUM|LOW
          expected_delta: {D1:+x, D5:+y, ...}
          rationale: str
          citations: [url]
          blocks: [action_id]      # must be done first
          challenge_note: str | null
  projected_composite_after: float
  projected_slsa_after: int
```

## Final Deliverable (Output Format — the only user-facing prose)
```
# Software Supply Chain Security Report
## 1. Summary & headline score
<composite>/100 (confidence <x>) — <PASS|NON-COMPLIANT|HALTED>
SLSA level: <L> (target <required>), missing for next: <...>
## 2. Dimension scores (with evidence/assumptions)
| Dimension | Score | Evidence / Assumptions |
... one row per dimension ...
## 3. Findings (strengths, gaps, risks)
- Strengths: ...
- Gaps: ...
- Risks: ...
## 4. Compliance status
gate: PASS|FAIL|HALTED; violations enumerated; regulatory flags (informational).
## 5. Prioritized roadmap (impact × effort)
| Wave | Action | Class | Impact | Effort | Priority | Risk if skip | Rationale | Citation |
...
## 6. Sources & assumptions
full citation list; explicit assumptions list; degradation flags.
## 7. Devil's-advocate review
objections raised; how addressed; residual uncertainty.
## Disclaimer
Informational analysis only; not professional legal/financial/tax/accounting advice.
Verify with a licensed professional before acting.
```

## Evidence & Assumption Rules
- Every roadmap action cites the framework control or advisory it addresses.
- Expected dimension deltas are estimates labeled `estimate`; not promises.
- `projected_composite_after` is a modeled projection, disclosed as such.

## Quality Gate
- [ ] Roadmap sorted by priority; waves assigned.
- [ ] Every action has impact_score, effort_score, priority, rationale, citation.
- [ ] Conflicts/dependencies resolved (no superseded duplicate actions).
- [ ] Devil's-advocate resolutions folded in.
- [ ] Final deliverable follows the Output Format exactly; disclaimer present.
- [ ] Compliance status reflected in headline; no sanitized NON-COMPLIANT output.
- [ ] All upstream quality gates already passed (intake/vuln/compliance/scoring).

## Hand-off
This is the terminal stage. The report is presented to the user only after `main.md` confirms all quality gates passed.
