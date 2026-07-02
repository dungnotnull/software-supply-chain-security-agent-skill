# CLAUDE.md — Software Supply Chain Security Scanning

**Skill name:** `software-supply-chain-security`
**Source idea:** #207 (ideas.md)
**Cluster:** Software, Code & Infra (`software-devops`)
**Tagline:** Scans the software supply chain for vulnerable, malicious or non-compliant dependencies and hardens it against SLSA standards.
**Current phase:** Phase 5 complete — all phases (0–5) done; production-grade, open-source ready.

## Problem This Skill Solves
Third-party dependencies introduce vulnerabilities, malicious packages and license risk. This skill audits dependencies, build pipelines and provenance, scoring against SLSA and recognized standards, and produces a prioritized hardening plan.

## Harness Flow Summary
1. **Intake** → `sub-inventory-intake` normalizes manifests/lockfiles/SBOM/pipeline/provenance/policy.
2. **Research / evidence sync** → consult `SECOND-KNOWLEDGE-BRAIN.md`; refresh via WebSearch/WebFetch when available (graceful degradation otherwise).
3. **Gate** → compliance check (`sub-compliance-check`): `HALTED` ⇒ no deliverable; `FAIL` ⇒ NON-COMPLIANT label; `PASS` ⇒ proceed.
4. **Analysis / scoring** → `sub-supplychain-scoring` scores six dimensions + SLSA level + disclosed-weight composite.
5. **Challenge** → devil's-advocate review challenges weakest assumptions and false positives.
6. **Synthesize** → `sub-hardening-roadmap` produces the scored deliverable + prioritized impact×effort roadmap.

**Compliance gate:** `sub-compliance-check` MUST pass (or be labeled NON-COMPLIANT) before the final deliverable is emitted. Output is informational, not professional/legal/financial advice.

## Sub-skills
- `skills/sub-inventory-intake.md` — Capture dependency manifests, build pipeline config, registries and provenance metadata.
- `skills/sub-vuln-scanner.md` — Identify known-vulnerable, abandoned, malicious or typosquatted dependencies; rank by CVSS×EPSS×reachability.
- `skills/sub-compliance-check.md` — Check license compliance and policy violations across the dependency tree (the compliance gate).
- `skills/sub-supplychain-scoring.md` — Score against SLSA level and OWASP CICD/Dependency risks.
- `skills/sub-hardening-roadmap.md` — Prioritize fixes (pin/upgrade, sign, isolate) by exploitability and effort.

## Evaluation Frameworks (world-renowned, citable)
- **SLSA (Supply-chain Levels for Software Artifacts)** — Graded framework (levels 1-4) for build integrity and provenance.
- **SBOM (SPDX / CycloneDX)** — Software bill-of-materials standards for dependency transparency.
- **OWASP Dependency / CICD Top 10** — Common dependency and pipeline risks and controls.
- **CVE / CVSS / EPSS prioritization** — Vulnerability scoring and exploit-likelihood prioritization.
- **Sigstore / provenance attestation** — Signing and verifying artifact provenance to defeat tampering.

## Tools Required
- `WebSearch`, `WebFetch` — live evidence and trend updates (graceful degradation to the knowledge brain when unavailable).
- `Read`, `Write` — load the knowledge brain; emit the deliverable.
- `Bash` — run `tools/knowledge_updater.py` (crawl pipeline).

## Knowledge Sources
- **ArXiv / academic categories:** cs.CR, cs.SE
- [SLSA framework](https://slsa.dev/) — Supply-chain integrity levels.
- [OWASP Dependency-Check / CICD Top 10](https://owasp.org/) — Dependency and pipeline risk standards.
- [NVD / OSV vulnerability databases](https://osv.dev/) — Vulnerability advisories for dependencies.
- [Sigstore](https://www.sigstore.dev/) — Artifact signing and provenance.
- [CISA supply-chain guidance](https://www.cisa.gov/) — Government supply-chain security guidance.

## Supporting Tools
- `tools/knowledge_updater.py` — crawl4ai (optional) + stdlib urllib fallback pipeline that grows `SECOND-KNOWLEDGE-BRAIN.md` (recommended weekly cron; see `tools/README.md`).
- `tools/supplychain_logic.py` — pure-Python reference implementation of the deterministic harness logic (license classification, compliance gate, CVSS×EPSS×reachability priority, SLSA assignment, six-dimension scoring). Reusable by sibling skills (see `INTEGRATION.md`).

## Active Development Tasks
- [x] Scaffold all required deliverables
- [x] Define frameworks, sub-skills and scoring dimensions
- [x] Author knowledge brain v1 and crawl pipeline
- [x] Deepen all sub-skills to production-grade with I/O schemas, framework mappings and gates
- [x] Encode compliance gate (PASS/FAIL/HALTED) + devil's-advocate protocol in `skills/main.md`
- [x] Production-grade `knowledge_updater.py` (async crawl4ai + stdlib fallback, CLI, dedupe, scoring) + `tools/README.md`
- [x] Reference logic module `tools/supplychain_logic.py` + `tests/test_harness.py` (41 passing tests, no network/model)
- [x] 10 test scenarios (5 primary + 5 adversarial/edge) in `tests/test-scenarios.md`
- [x] Cross-skill wiring: `INTEGRATION.md` shared sub-skill interfaces for `software-devops` cluster reuse
- [ ] First scheduled live crawl (operational, not a build task)

## Related Root Docs
- `PROJECT-detail.md` — full technical spec
- `PROJECT-DEVELOPMENT-PHASE-TRACKING.md` — phase roadmap
- `SECOND-KNOWLEDGE-BRAIN.md` — living domain knowledge base
- `INTEGRATION.md` — shared sub-skill interfaces for cluster reuse
- `README.md` — open-source project README
