---
name: software-supply-chain-security__sub-supplychain-scoring
description: Sub-skill of software-supply-chain-security — Score the supply chain across six evidence-backed dimensions using SLSA, SBOM, OWASP CICD/Dependency Top 10, CVSS/EPSS and Sigstore; produce a transparent weighted composite with disclosed weights.
---

## Purpose
Turn the enriched `InventoryRecord`, `VulnScanReport` and `ComplianceReport` into a multi-dimensional score (0–100 per dimension, 0–100 composite) plus a SLSA level assessment. Every dimension score must be traceable to a cited source or an explicit assumption. Weights are disclosed and adjustable.

## Inputs
- `InventoryRecord` (dependencies, pipeline, provenance signals, coverage).
- `VulnScanReport` (priorities, abandonment, typosquat).
- `ComplianceReport` (gate_status, violations, license summary).
- `SECOND-KNOWLEDGE-BRAIN.md` framework references.

## Frameworks Applied (and how each maps to a dimension)

| Dimension | Primary framework(s) | What it measures |
|-----------|---------------------|------------------|
| Known-vulnerability exposure | CVSS v3 + EPSS + OSV/NVD | Weighted exploit-likelihood of known CVEs |
| Malicious / typosquat risk | OWASP A08/A09 + sockets/checkmarx intel + typosquat heuristics | Likelihood a dep is malicious or impersonating |
| License compliance | SPDX + org policy + EU CRA/SBOM obligations | Policy/obligation compliance of the license tree |
| Provenance / SLSA level | **SLSA** (levels 1–4) | Build integrity & provenance maturity |
| Pipeline hardening | **OWASP CICD Top 10** + SLSA build track | CI/CD attack-surface hardening |
| Patch responsiveness | CVSS/EPSS + NVD publish→fix lag + maintainer signals | Speed & feasibility of fixing vulns |

## Scoring Procedure (deterministic; show the math)

### SLSA Level Assessment (first, since provenance score depends on it)
Use the canonical SLSA build-track levels:

| Level | Requirements (build) |
|-------|----------------------|
| L1 | Build process documented (scripted); provenance generated (untrusted) |
| L2 | Managed build service; hosted provenance generated & tamper-resistant; version-controlled source |
| L3 | Hardened, isolated, hermetic build; provenance is non-falsifiable; two-party reviewed source |
| L4 | Reproducible build; hermetic, isolated; two-party review; person-of-record; provenance verifiably matches |

Inspect `provenance_signals` per artifact and the pipeline block. Assign the **lowest** level that all required signals satisfy (no partial credit up). Record `slsa_level` and the missing signals that prevent the next level.

### Per-dimension scoring (0–100, higher is better/safer)

**D1 Known-vulnerability exposure**
```
penalty = Σ over findings of (priority_raw * weight_by_band)   # HIGH=1.0, MEDIUM=0.6, LOW=0.3
normalized = penalty / max(1, dependency_count)                # per-dep load
D1 = clamp(100 * (1 - normalized), 0, 100)
```
Source: CVSS (NVD/OSV) + EPSS (FIRST.org). If EPSS missing for all, tag assumption and substitute `epss=0` (conservative for triage, anti-conservative for severity — disclose the substitution).

**D2 Malicious / typosquat risk**
```
risk = max over deps of typosquat_risk, plus +0.2 if any malicious_advisory_hits
D2 = clamp(100 * (1 - risk), 0, 100)
```
Heuristics defined in `sub-vuln-scanner`. Cite advisory hits; mark heuristic-only findings as `assumption`.

**D3 License compliance**
```
base = 100
- 25 per strong/network copyleft dep (unless allowlisted)
- 40 per UNKNOWN/NONE/UNLICENSED dep (policy blocker)
- 10 per weak-copyleft dep if not allowed
- if ComplianceReport.gate_status == FAIL: cap D3 at 40
D3 = clamp(base, 0, 100)
```
Source: SPDX license list + org policy.

**D4 Provenance / SLSA level**
```
target = policy.required_slsa_level (default 3)
D4 = clamp(100 * slsa_level / target, 0, 100)   # exceeding target caps at 100
```
If no provenance at all (L0), `slsa_level=0` ⇒ D4=0 and `degraded=true`. Source: slsa.dev spec.

**D5 Pipeline hardening** — audit vs OWASP CICD Top 10 (CICD-SEC-01..10). For each control satisfied add 10; for each violation subtract per severity. Base 100.
```
violations_penalty = Σ (hard=20, soft=8)
controls_met = count of CICD-SEC-01..10 satisfied
D5 = clamp(100 - violations_penalty + max(0, controls_met-5)*2 - (10-controls_met)*10, 0, 100)
```
OWASP CICD Top 10 map (each control = a checklist item):
- CICD-SEC-01 Insufficient flow control → branch protection, required reviews present?
- CICD-SEC-02 Poisoned pipeline execution → injection from PR-controlled inputs?
- CICD-SEC-03 Dependency confusion → private-vs-public registry precedence, lockfile pinned?
- CICD-SEC-04 Excessive permissions → least-privilege tokens, OIDC?
- CICD-SEC-05 Secret management → no plaintext secrets, masked logs, vault?
- CICD-SEC-06 Identity & access → SSO, 2FA on maintainers?
- CICD-SEC-07 Webhook & integration abuse → webhook secrets validated?
- CICD-SEC-08 Self-hosted runner abuse → ephemeral runners, no persistent tokens?
- CICD-SEC-09 Two-factor enforcement → required for merge/publish?
- CICD-SEC-10 Codecov-style supply-chain injection → provenance verified, runner image pinned to digest?

**D6 Patch responsiveness**
```
lag = Σ |patch_responsiveness_proxy| over fixable findings
D6 = clamp(100 - lag * k, 0, 100)   # k = 0.5 (tunable)
abandoned penalty: -15 per abandoned dep
```
Source: NVD publish dates + maintainer signals.

### Composite (weights disclosed, default below, adjustable via policy.scoring_weights)
```
weights = {D1:0.25, D2:0.15, D3:0.15, D4:0.20, D5:0.15, D6:0.10}   # sum=1.0
composite = Σ weights[d] * D[d]
confidence = f(coverage.percent_enriched, advisory_sources_used, degraded)
   confidence = 0.5 + 0.5 * coverage_percent_enriched; -0.2 if degraded; clamp 0..1
```
If `ComplianceReport.gate_status == FAIL`, composite is still computed but the report headline is prefixed **NON-COMPLIANT** and the violations are listed first.

## Output Schema
```yaml
ScoringReport:
  scored_at: ISO-8601
  weights: {D1:.., D2:.., D3:.., D4:.., D5:.., D6:..}
  slsa_level: 0|1|2|3|4
  slsa_missing_signals_for_next_level: [str]
  dimensions:
    D1_known_vuln_exposure: {score, evidence:[], assumptions:[]}
    D2_malicious_typosquat: {score, evidence:[], assumptions:[]}
    D3_license_compliance: {score, evidence:[], assumptions:[]}
    D4_provenance_slsa: {score, slsa_level, evidence:[], assumptions:[]}
    D5_pipeline_hardening: {score, owasp_controls:{met:[], unmet:[]}, evidence:[]}
    D6_patch_responsiveness: {score, evidence:[], assumptions:[]}
  composite: float
  confidence: float
  headline: str          # e.g. "Composite 72/100 (confidence 0.78) — NON-COMPLIANT"
  degraded: bool
```

## Evidence & Assumption Rules
- Each dimension's `evidence[]` contains ≥1 citation (`osv.dev/CVE-...`, `slsa.dev/spec`, `owasp.org/...`, SPDX) or an `assumptions[]` entry.
- Substitutions (e.g. EPSS→0) are recorded in `assumptions[]` with the formula impact noted.
- SLSA level claim must list exactly which signals satisfied each requirement and which were missing.

## Quality Gate
- [ ] All six dimensions scored; none blank.
- [ ] Composite uses disclosed weights summing to 1.0.
- [ ] SLSA level assigned with missing-for-next-level signals listed.
- [ ] OWASP CICD controls enumerated as met/unmet.
- [ ] Every dimension has evidence or assumption; no uncited score.
- [ ] FAIL status propagated to headline; no sanitized output.
- [ ] Confidence reflects degradation/coverage honestly.

## Hand-off
Downstream: `sub-hardening-roadmap` consumes `ScoringReport` + violations + slsa gap to build the prioritized roadmap; `main.md` runs the devil's-advocate pass on this report.
