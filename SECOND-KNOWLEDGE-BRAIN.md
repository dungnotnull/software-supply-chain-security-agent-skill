# SECOND-KNOWLEDGE-BRAIN.md — Software Supply Chain Security Scanning

> Self-improving domain knowledge base for `software-supply-chain-security` (idea #207). Grown by `tools/knowledge_updater.py`.

## Core Concepts & Frameworks
### SLSA (Supply-chain Levels for Software Artifacts)
Graded framework (levels 1-4) for build integrity and provenance. Build track requirements: L1 provenance generated; L2 managed build + tamper-resistant provenance + version-controlled source; L3 hardened/isolated/hermetic build + non-falsifiable provenance + two-party review; L4 reproducible + hermetic + person-of-record. Source: https://slsa.dev/spec

### SBOM (SPDX / CycloneDX)
Software bill-of-materials standards for dependency transparency. SPDX: https://spdx.org/licenses/ ; CycloneDX: https://cyclonedx.org/ . Mandated for US federal software under EO 14028 and addressed by the EU Cyber Resilience Act.

### OWASP Dependency / CICD Top 10
Common dependency and pipeline risks and controls. CICD-SEC-01 Insufficient flow control; -02 Poisoned pipeline execution; -03 Dependency confusion; -04 Excessive permissions; -05 Secret management; -06 Identity & access; -07 Webhook/integration abuse; -08 Self-hosted runner abuse; -09 Two-factor enforcement; -10 Supply-chain injection. Source: https://owasp.org/www-project-top-10-ci-cd-security-risks/

### CVE / CVSS / EPSS prioritization
Vulnerability severity (CVSS v3.1, https://www.first.org/cvss/ ) and exploit-likelihood (EPSS, https://www.first.org/epss/ ). OSV.dev (https://osv.dev/ ) and NVD (https://nvd.nist.gov/ ) provide machine-readable advisories.

### Sigstore / provenance attestation
Signing and verifying artifact provenance to defeat tampering. cosign + Rekor + Fulcio; keyless OIDC signing. Source: https://www.sigstore.dev/


## Key Research Papers
| Title | Authors | Year | Venue | Link | Relevance |
|-------|---------|------|-------|------|-----------|
| Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks | Ohm, Plate, Sykosch, Meier | 2020 | DIMVA | https://doi.org/10.1007/978-3-030-52683-2_23 | Foundational taxonomy of OSS supply-chain attacks (typosquatting, dependency confusion, compromised build). |
| Towards Measuring Supply Chain Attacks on Package Managers for Source Code | Ohm | 2020 | arXiv | https://arxiv.org/abs/2003.10229 | Detection methodology for malicious packages in npm/PyPI. |
| Software Supply Chain Attacks: A Systematic Mapping Study | Ladisa, Plate, Martinez, Barais | 2022 | JSS | https://doi.org/10.1016/j.jss.2022.111019 | Systematic review and taxonomy of supply-chain attack vectors (SLSA-aligned). |
| A Look Into the Provenance of Software Supply Chain Attacks | Vu, Pashchenko, Massacci, Plate, Sabetta | 2021 | ESEC/FSE | https://doi.org/10.1145/3468264.3473925 | Provenance and build-integrity gaps that SLSA addresses. |

The crawl pipeline appends further entries below, ranked by recency × relevance.

## State-of-the-Art Methods & Tools
- Apply the frameworks above as the scoring backbone.
- Prefer the highest available evidence tier (systematic review > meta-analysis > RCT/standard > expert opinion > blog).
- Refresh trend-sensitive figures (advisory counts, EPSS distributions, benchmark thresholds) at analysis time via WebSearch.
- Detection tooling: OSV-Scanner, govulncheck, pip-audit, npm audit / sockets.dev, Trivy, Syft (SBOM), cosign (signing), slsa-verifier (provenance).

## Authoritative Data Sources
| Source | Why it matters |
|--------|----------------|
| [SLSA framework](https://slsa.dev/) | Supply-chain integrity levels (L1–L4). |
| [OWASP CICD Top 10](https://owasp.org/) | Dependency and pipeline risk standards. |
| [NVD / OSV vulnerability databases](https://osv.dev/) | Vulnerability advisories for dependencies. |
| [Sigstore](https://www.sigstore.dev/) | Artifact signing and provenance. |
| [CISA supply-chain guidance](https://www.cisa.gov/) | Government supply-chain security guidance. |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit prediction scoring for prioritization. |
| [SPDX license list](https://spdx.org/licenses/) | Canonical open-source license identifiers. |

## Analytical Frameworks (used for scoring)
- **SLSA (Supply-chain Levels for Software Artifacts)**
- **SBOM (SPDX / CycloneDX)**
- **OWASP Dependency / CICD Top 10**
- **CVE / CVSS / EPSS prioritization**
- **Sigstore / provenance attestation**

Scoring dimensions derived from these frameworks: Known-vulnerability exposure, Malicious/typosquat risk, License compliance, Provenance/SLSA level, Pipeline hardening, Patch responsiveness.

## Self-Update Protocol
- **Crawl sources:** ArXiv (cs.CR, cs.SE) + the authoritative domain sources above.
- **Search queries:**
- `software supply chain attack trends 2026`
- `dependency confusion typosquatting detection`
- `SLSA provenance adoption`
- `EPSS exploit prediction vulnerability prioritization`
- **Frequency:** weekly (cron / Windows scheduled task — see `tools/README.md`).
- **Append format:** `### [YYYY-MM-DD] <title>` with Authors, Venue, Link, Key finding, Relevance score (0–1), Source-hash (dedupe).
- **Dedupe:** skip entries whose URL hash already exists (`tools/knowledge_updater.py`).

## Knowledge Update Log
- **2026-06-18** — Knowledge brain v1 seeded with core frameworks, sources and crawl config for idea #207.
- **2026-07-02** — Brain finalized for open-source release: seeded foundational references (Ohm et al. DIMVA 2020; Ohm arXiv 2020; Ladisa et al. JSS 2022; Vu et al. ESEC/FSE 2021), expanded SLSA/OWASP-CICD/EPSS/SPDX reference detail, and detection-tooling list. Live refresh runs via the weekly pipeline (`tools/knowledge_updater.py`).
