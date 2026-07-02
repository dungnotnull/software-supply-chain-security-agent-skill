# INTEGRATION.md — Cross-Skill Wiring for the `software-devops` Cluster

This document defines the **shared sub-skill interfaces** exposed by
`software-supply-chain-security` so that sibling skills in the
**Software, Code & Infra (`software-devops`)** cluster can reuse its
intake, scoring and roadmap stages instead of re-implementing them.

## Design principle
The harness is composed of sub-skills with explicit, typed input/output
contracts (see the YAML schemas in each `skills/sub-*.md`). Three of these
are intentionally **generic enough for cluster-wide reuse**:

| Reusable sub-skill | What it provides to siblings | Reusable artifact |
|--------------------|------------------------------|-------------------|
| `sub-inventory-intake` | A normalized `InventoryRecord` schema (manifests, pipeline, policy, env, coverage) that any devops skill can populate. | `InventoryRecord` YAML schema |
| `sub-supplychain-scoring` | A six-dimension, disclosed-weight scoring engine with a SLSA/OWASP/CVSS/EPSS backbone — reusable as a scoring layer for any "audit + score" devops skill. | `tools/supplychain_logic.py` (pure functions) + scoring weights |
| `sub-hardening-roadmap` | An impact×effort prioritized roadmap builder (action catalog + priority formula + waves). Reusable for any "produce a fix plan" devops skill. | Roadmap schema + action catalog |

## Shared interfaces (contracts)

### 1. Intake contract (`InventoryRecord`)
Sibling skills may **produce** an `InventoryRecord` (or a subset) and hand it
to this skill's downstream stages, or **consume** the schema to capture their
own inventory. Required fields are declared in
`skills/sub-inventory-intake.md` → "Output Schema". The minimal reusable
surface is:

```yaml
InventoryRecord:
  scope, env_context, policy, dependencies[], pipeline, coverage, degradation_flags
```

A sibling skill that only cares about pipeline hardening can populate
`pipeline` + `policy` and set `scope: pipeline-only`; the scoring engine
degrades missing dimensions gracefully (records `degraded=true`).

### 2. Scoring interface (`supplychain_logic.py`)
The deterministic scoring layer is published as importable pure functions in
`tools/supplychain_logic.py` so sibling skills can reuse **without copying**:

```python
import supplychain_logic as sc

report = sc.compliance_check(inventory, vulns)        # ComplianceReport
scoring = sc.score_dimensions(inventory, vulns, report)  # composite + dims + SLSA
raw, band, assumption = sc.compute_priority(cvss, epss, reachability, assumed)
level, missing = sc.assign_slsa_level(provenance_signals)
category = sc.classify_license(spdx_expression)
```

Sibling skills that want **different dimensions** can reuse the framework
plugs (SLSA, OWASP CICD, CVSS/EPSS, SPDX) and swap only the dimension set,
keeping the disclosed-weight composite + confidence model.

### 3. Roadmap interface
The roadmap action catalog (`pin | upgrade | sign | provenance | isolate |
policy | replace | monitor`) and the `priority = impact_score / effort_score`
model in `skills/sub-hardening-roadmap.md` are framework-agnostic. Sibling
devops skills (e.g. a "secure-iac" or "container-hardening" skill) can reuse
the catalog and the Wave 0–3 sequencing by mapping their own findings to the
action classes.

## Reuse patterns for the `software-devops` cluster

| Sibling skill (example) | Reuses from this skill | How |
|--------------------------|------------------------|-----|
| `cicd-pipeline-audit` | intake (`pipeline`), scoring (`D5` + OWASP CICD map), roadmap | Populate `pipeline`+`policy`, set `scope: pipeline-only`, import `supplychain_logic._owasp_controls_met` + `score_dimensions`. |
| `dependency-license-compliance` | intake (`dependencies[].license`, `policy`), compliance gate, roadmap | Import `classify_license` + `compliance_check`; reuse the HALTED/FAIL/PASS decision logic. |
| `artifact-provenance-attestation` | intake (`provenance_signals`), scoring (`D4` + SLSA), roadmap (`sign`/`provenance`) | Import `assign_slsa_level`; reuse SLSA L1–L4 requirement sets. |
| `vuln-triage-fast` | vuln scanner priority model, roadmap Wave 0 | Import `compute_priority`; reuse the priority-band + action catalog for "what first". |

## Interface stability guarantees
- The `InventoryRecord`, `ComplianceReport`, `ScoringReport` and `Roadmap`
  YAML schemas are **versioned via the `policy_version` / report timestamps**;
  breaking changes require a schema bump noted in this file.
- `tools/supplychain_logic.py` keeps a stable function surface
  (`compliance_check`, `score_dimensions`, `compute_priority`,
  `assign_slsa_level`, `classify_license`) — additive changes only within a
  minor version; covered by `tests/test_harness.py`.
- The knowledge brain (`SECOND-KNOWLEDGE-BRAIN.md`) is a shared read-only
  knowledge substrate for the whole cluster; the crawl pipeline
  (`tools/knowledge_updater.py`) is configurable per skill via its JSON config.

## How a sibling skill wires in (quick start)
1. Add `software-supply-chain-security/tools` to the sibling's Python path.
2. Populate an `InventoryRecord` (full or `pipeline-only`/`single-package`).
3. Call `supplychain_logic.compliance_check` → gate. On `HALTED`, stop.
4. Call `supplychain_logic.score_dimensions` → composite + dimensions + SLSA.
5. Map findings to the roadmap action catalog; prioritize via
   `impact_score / effort_score`; emit waves 0–3.
6. Reuse the quality gates from `skills/main.md` (every dimension cited or
   assumption-marked; devil's-advocate pass; disclaimer).

## Success criteria for Phase 5
- [x] Shared sub-skill interfaces documented (intake, scoring, roadmap).
- [x] Reusable executable layer published (`tools/supplychain_logic.py`).
- [x] Reuse patterns enumerated for ≥4 sibling skills in the cluster.
- [x] Interface stability guarantees stated.
- [x] Sibling skills can reuse intake/scoring/roadmap patterns without
      re-implementing the framework backbone.
