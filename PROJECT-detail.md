# PROJECT-detail.md — Software Supply Chain Security Scanning

## Executive Summary
`software-supply-chain-security` is a harness skill in the **Software, Code & Infra** cluster (idea #207). Scans the software supply chain for vulnerable, malicious or non-compliant dependencies and hardens it against SLSA standards. It executes a research-first, framework-grounded workflow that ends in a multi-dimensional score and a prioritized, effort/impact-ranked improvement roadmap.

> **Disclaimer:** This skill provides informational analysis only and is **not** professional legal, financial, tax or accounting advice. Verify with a licensed professional before acting.

## Problem Statement
Third-party dependencies introduce vulnerabilities, malicious packages and license risk. This skill audits dependencies, build pipelines and provenance, scoring against SLSA and recognized standards, and produces a prioritized hardening plan.

## Target Users & Use Cases
- Practitioners, learners and small teams who need an expert-grade, evidence-based analysis without hiring a specialist.
- Trigger examples:
  - "We have 200 CVEs, what first?" → the skill runs its full harness and returns a scored deliverable.
  - "Is this new dependency safe?" → the skill runs its full harness and returns a scored deliverable.
  - "Did we pull in GPL code?" → the skill runs its full harness and returns a scored deliverable.
  - "How do we reach SLSA level 3?" → the skill runs its full harness and returns a scored deliverable.
  - "Secure our CI/CD" → the skill runs its full harness and returns a scored deliverable.

## Harness Architecture
```
User input
   │
   ▼
[Stage 1 Intake]  sub-inventory-intake
   │
   ▼
[Stage 2 Research]  SECOND-KNOWLEDGE-BRAIN.md + WebSearch/WebFetch
   │
   ▼
[Stage 3 Gate]  sub-compliance-check
   │
   ▼
[Stage 4 Scoring]  sub-supplychain-scoring  → score vs frameworks
   │
   ▼
[Stage 5 Challenge]  devil's-advocate review
   │
   ▼
[Stage 6 Synthesis]  sub-hardening-roadmap  → scored report + roadmap
```

## Full Sub-Skill Catalog
### `sub-inventory-intake`
- **Purpose:** Capture dependency manifests, build pipeline config, registries and provenance metadata.
- **Inputs:** structured fields from prior stages / user.
- **Outputs:** structured record consumed by the next stage.
- **Tools:** Read, WebSearch/WebFetch (as needed).
- **Quality gate:** outputs are complete, evidence-linked, and assumptions are explicit.
### `sub-vuln-scanner`
- **Purpose:** Identify known-vulnerable, abandoned, malicious or typosquatted dependencies.
- **Inputs:** structured fields from prior stages / user.
- **Outputs:** structured record consumed by the next stage.
- **Tools:** Read, WebSearch/WebFetch (as needed).
- **Quality gate:** outputs are complete, evidence-linked, and assumptions are explicit.
### `sub-compliance-check`
- **Purpose:** Check license compliance and policy violations across the dependency tree.
- **Inputs:** structured fields from prior stages / user.
- **Outputs:** structured record consumed by the next stage.
- **Tools:** Read, WebSearch/WebFetch (as needed).
- **Quality gate:** outputs are complete, evidence-linked, and assumptions are explicit.
### `sub-supplychain-scoring`
- **Purpose:** Score against SLSA level and OWASP CICD/Dependency risks.
- **Inputs:** structured fields from prior stages / user.
- **Outputs:** structured record consumed by the next stage.
- **Tools:** Read, WebSearch/WebFetch (as needed).
- **Quality gate:** outputs are complete, evidence-linked, and assumptions are explicit.
### `sub-hardening-roadmap`
- **Purpose:** Prioritize fixes (pin/upgrade, sign, isolate) by exploitability and effort.
- **Inputs:** structured fields from prior stages / user.
- **Outputs:** structured record consumed by the next stage.
- **Tools:** Read, WebSearch/WebFetch (as needed).
- **Quality gate:** outputs are complete, evidence-linked, and assumptions are explicit.

## Evaluation Frameworks
1. **SLSA (Supply-chain Levels for Software Artifacts)** — Graded framework (levels 1-4) for build integrity and provenance.
2. **SBOM (SPDX / CycloneDX)** — Software bill-of-materials standards for dependency transparency.
3. **OWASP Dependency / CICD Top 10** — Common dependency and pipeline risks and controls.
4. **CVE / CVSS / EPSS prioritization** — Vulnerability scoring and exploit-likelihood prioritization.
5. **Sigstore / provenance attestation** — Signing and verifying artifact provenance to defeat tampering.

## Scoring Dimensions
- Known-vulnerability exposure
- Malicious/typosquat risk
- License compliance
- Provenance/SLSA level
- Pipeline hardening
- Patch responsiveness

Each dimension is scored 0–100 (or 1–5) with an explicit rationale and at least one cited source or stated assumption. The composite score is a transparent weighted aggregate; weights are disclosed.

## Skill File Format Specification
- Frontmatter: `name` (= `software-supply-chain-security`), `description` (one line).
- Required sections: Role & Persona, Workflow (Harness Flow), Sub-skills Available, Tools, Output Format, Quality Gates.

## E2E Execution Flow
1. Parse request; classify the task and detect missing inputs (ask targeted questions).
2. Run intake sub-skill → structured profile.
3. Sync evidence from the knowledge brain; refresh via WebSearch/WebFetch when available; otherwise signal degraded mode.
4. Run the compliance gate — **halt and route out** on red flags.
5. Score against frameworks; record evidence per dimension.
6. Devil's-advocate pass: challenge weakest assumptions, seek disconfirming evidence.
7. Synthesize the deliverable: scored report + prioritized roadmap (effort × impact).
8. Run quality gates; only then present output.

## SECOND-KNOWLEDGE-BRAIN Integration
- Sources: ArXiv (cs.CR, cs.SE) + the authoritative domain sources listed in `CLAUDE.md`.
- Crawl config and append format are defined in `tools/knowledge_updater.py` and `SECOND-KNOWLEDGE-BRAIN.md`.

## Supporting Tools Spec — `knowledge_updater.py`
- **Inputs:** crawl query list (below), source URLs, last-run timestamp.
- **Outputs:** appended, de-duplicated, date-stamped entries in `SECOND-KNOWLEDGE-BRAIN.md`.
- **Schedule:** weekly cron.
- **Crawl queries:** `software supply chain attack trends 2026`, `dependency confusion typosquatting detection`, `SLSA provenance adoption`, `EPSS exploit prediction vulnerability prioritization`

## Quality Gates (must all pass before output)
- Every scored dimension cites a source or states an assumption.
- The applicable safety/compliance gate has passed.
- The devil's-advocate review has been performed and its objections addressed.
- The roadmap items are prioritized by effort × impact and are actionable.
- Evidence hierarchy respected (systematic review > meta-analysis > RCT/standard > expert opinion > blog).

## Test Scenarios
1. **Vuln triage** — *User:* "We have 200 CVEs, what first?" → *Skill:* Prioritizes by CVSS+EPSS+reachability. (**Gate:** Prioritization uses exploit-likelihood, not just CVSS.)
2. **Malicious package** — *User:* "Is this new dependency safe?" → *Skill:* Checks typosquat/maintainer/provenance signals. (**Gate:** Suspicious package flagged before adoption.)
3. **License risk** — *User:* "Did we pull in GPL code?" → *Skill:* Scans license tree for policy violations. (**Gate:** License compliance reported explicitly.)
4. **SLSA goal** — *User:* "How do we reach SLSA level 3?" → *Skill:* Scores current level, sequences provenance steps. (**Gate:** Level claim tied to evidence.)
5. **Pipeline hardening** — *User:* "Secure our CI/CD" → *Skill:* Audits pipeline vs OWASP CICD Top 10. (**Gate:** Pipeline risks mapped to controls.)

## Key Design Decisions
1. Research-first: no scored claim without a citation or explicit assumption.
2. Framework-grounded: scoring uses only the named world-renowned frameworks above.
3. Composable sub-skills (≥3) with explicit gates between stages.
4. Self-improving knowledge brain via the crawl pipeline.
5. Graceful degradation when WebSearch/WebFetch are unavailable.
