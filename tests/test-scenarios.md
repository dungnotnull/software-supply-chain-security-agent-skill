# tests/test-scenarios.md — Software Supply Chain Security Scanning

Scenario + adversarial/edge-case suite for `software-supply-chain-security`
(idea #207). 10 scenarios: 5 primary use-cases, 5 adversarial/edge cases.
Each declares inputs, expected harness behavior, frameworks exercised, the
quality gate under test, and explicit pass criteria. The executable checks
live in `tests/test_harness.py` and validate the deterministic logic
(scoring formulas, gate decision logic, dedupe, relevance) used by the
sub-skills — they require **no network and no model**.

## Primary scenarios (1–5)

### Scenario 1: Vuln triage
- **User input:** "We have 200 CVEs, what first?"
- **Expected harness behavior:** Prioritizes by CVSS × EPSS × reachability, not raw CVSS.
- **Frameworks exercised:** CVSS/EPSS, OSV/NVD, OWASP Dependency Top 10.
- **Gate under test:** Prioritization uses exploit-likelihood (priority_band), not CVSS alone.
- **Pass criteria:** every finding carries `priority_raw` from the documented formula; `priority_band` derived from it; top-10 by priority in the roadmap Wave 0.

### Scenario 2: Malicious package
- **User input:** "Is this new dependency safe?" (single fresh dep)
- **Expected harness behavior:** Checks typosquat/maintainer-age/provenance signals; flags before adoption.
- **Frameworks exercised:** OWASP A08/A09, typosquat heuristics, Sigstore provenance.
- **Gate under test:** Suspicious package flagged before adoption (typosquat_risk ≥ 0.5 → roadmap `replace`/review).
- **Pass criteria:** `typosquat_risk` is numeric with listed signals; no bare boolean; recommendation gated on risk score.

### Scenario 3: License risk
- **User input:** "Did we pull in GPL code?"
- **Expected harness behavior:** Scans license tree for policy violations; classifies per SPDX.
- **Frameworks exercised:** SPDX, org policy, EU CRA/SBOM obligations.
- **Gate under test:** License compliance reported explicitly; strong/network copyleft or UNKNOWN are violations.
- **Pass criteria:** D3 reflects violations; `ComplianceReport.gate_status` is FAIL when GPL present and not allowlisted; headline prefixed NON-COMPLIANT.

### Scenario 4: SLSA goal
- **User input:** "How do we reach SLSA level 3?"
- **Expected harness behavior:** Scores current SLSA level; sequences provenance steps to reach target.
- **Frameworks exercised:** SLSA L1–L4, Sigstore provenance.
- **Gate under test:** Level claim tied to evidence (signals listed; missing-for-next-level listed).
- **Pass criteria:** `slsa_level` assigned; `slsa_missing_signals_for_next_level` enumerated; roadmap Wave 2/3 sequences the steps.

### Scenario 5: Pipeline hardening
- **User input:** "Secure our CI/CD"
- **Expected harness behavior:** Audits pipeline vs OWASP CICD Top 10 (CICD-SEC-01..10).
- **Frameworks exercised:** OWASP CICD Top 10, SLSA build track.
- **Gate under test:** Pipeline risks mapped to controls (met/unmet per control).
- **Pass criteria:** D5 lists `owasp_controls.met`/`unmet`; each violation mapped to a control ID and a remediation action class.

## Adversarial & edge cases (6–10)

### Scenario 6: Degraded mode (offline)
- **User input:** any primary scenario with WebSearch/WebFetch unavailable.
- **Expected harness behavior:** Falls back to `SECOND-KNOWLEDGE-BRAIN.md`; sets `degraded=true`; lowers `confidence` by 0.2 (floor 0); declares degraded mode in the report.
- **Gate under test:** No fabricated live data; degradation disclosed.
- **Pass criteria:** `degraded=true` on every report; no `advisory_url` claims a live fetch; disclaimer-of-degradation present.

### Scenario 7: Insufficient input
- **User input:** a vague one-line request missing manifests/policy.
- **Expected harness behavior:** Intake asks ranked clarifying questions; no scored output until blockers gathered.
- **Gate under test:** No assumption of missing blocker fields.
- **Pass criteria:** no `ScoringReport` emitted; `IntakeReport.missing_required_fields` populated; clarifying questions ranked (blockers first).

### Scenario 8: Compliance HALT (professional-scope ambiguity)
- **User input:** "Is AGPL-3.0 okay for our SaaS?" with no policy + no counsel.
- **Expected harness behavior:** Compliance gate HALTS; flags that resolving the license's legal effect needs qualified counsel; no scored deliverable.
- **Gate under test:** Halt-and-flag on professional-scope ambiguity (no unlicensed legal opinion).
- **Pass criteria:** `gate_status=HALTED`; `professional_scope_halt` populated; **no** deliverable emitted; re-prompt issued.

### Scenario 9: Adversarial false-positive inflation
- **User input:** manifest with a CVE whose affected range does NOT include the installed version, plus an EPSS-assumed (0.5 reachability) HIGH band.
- **Expected harness behavior (devil's advocate):** challenge the HIGH priority; reachability assumed → must be marked `reachability_assumption=true`; priority recomputed/flagged; no inflation to justify dramatic roadmap.
- **Gate under test:** Devil's-advocate catches false positives and assumption-driven inflation.
- **Pass criteria:** `reachability_assumption=true` on the finding; challenge section records the objection; roadmap not over-weighted by the false positive.

### Scenario 10: Dependency-confusion / registry-takeover trust challenge
- **User input:** private package also published publicly with a higher version; relies on "trusted internal registry".
- **Expected harness behavior (devil's advocate):** challenge the trusted-registry assumption; map to OWASP CICD-SEC-03; recommend private-registry precedence + lockfile pinning.
- **Gate under test:** Trust assumptions challenged; dependency-confusion risk surfaced.
- **Pass criteria:** challenge section flags the trust assumption; D5 reflects CICD-SEC-03 unmet; roadmap Wave 0 includes isolate/pin action with citation.

## Regression Checklist
- [ ] All gates enforced on every path (compliance: HALTED ⇒ no deliverable; FAIL ⇒ NON-COMPLIANT label).
- [ ] Scores trace to citations or explicit assumptions (no uncited dimension).
- [ ] Devil's-advocate review present on every run; false positives challenged.
- [ ] Roadmap prioritized by impact × effort; waves assigned.
- [ ] Composite weights disclosed and summing to 1.0.
- [ ] SLSA level claim lists satisfied + missing signals.
- [ ] Degraded mode declared; no fabricated live data.
- [ ] Disclaimer present on every deliverable.

## Executable validation
Run `pytest tests/test_harness.py` (no network, no model) to validate the
deterministic logic shared by the sub-skills:
priority-band classification, scoring formulas, license-classification → gate
decision logic, SLSA-level assignment, knowledge-updater relevance/recency/dedupe.
Fixtures: `tests/fixtures/sample_inventory.json`, `tests/fixtures/sample_vulns.json`.
