# software-supply-chain-security

> Scans the software supply chain for vulnerable, malicious or non-compliant
> dependencies and hardens it against SLSA standards. A research-first,
> framework-grounded harness skill in the **Software, Code & Infra
> (`software-devops`)** cluster (idea #207).

[![tests](https://img.shields.io/badge/tests-41%20passing-brightgreen)](tests/test_harness.py)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](tools/knowledge_updater.py)
[![license](https://img.shields.io/badge/license-MIT-green)](#license)

## What it does
Audits dependencies, build pipelines and artifact provenance, scores the supply
chain against world-renowned frameworks, and produces a prioritized,
effort×impact hardening plan.

**Evaluation frameworks:** SLSA · SBOM (SPDX/CycloneDX) · OWASP CICD Top 10 ·
CVE/CVSS/EPSS · Sigstore/provenance attestation.

## Repository layout
```
.
├── skills/                       # harness + sub-skills (authoritative spec)
│   ├── main.md                   #   harness flow, gates, devil's-advocate, output format
│   ├── sub-inventory-intake.md   #   normalize manifests/SBOM/pipeline/provenance/policy
│   ├── sub-vuln-scanner.md       #   CVE/CVSS×EPSS×reachability, typosquat heuristics
│   ├── sub-compliance-check.md   #   license/policy gate (PASS/FAIL/HALTED)
│   ├── sub-supplychain-scoring.md#   6-dimension scoring + SLSA + composite
│   └── sub-hardening-roadmap.md  #   prioritized impact×effort roadmap + final report
├── tools/
│   ├── knowledge_updater.py      # self-improving knowledge pipeline (crawl4ai + stdlib)
│   ├── supplychain_logic.py      # reference impl of the deterministic harness logic
│   ├── requirements.txt          # optional deps (runs with zero required packages)
│   └── README.md                 # updater usage + weekly cron / scheduled-task setup
├── tests/
│   ├── test-scenarios.md         # 10 scenarios (5 primary + 5 adversarial/edge)
│   ├── test_harness.py           # 41 pytest checks (no network, no model)
│   └── fixtures/                 # sample inventory + vuln scan
├── SECOND-KNOWLEDGE-BRAIN.md     # living domain knowledge base (grown by the updater)
├── INTEGRATION.md                # shared sub-skill interfaces for cluster reuse
├── PROJECT-detail.md             # full technical spec
├── PROJECT-DEVELOPMENT-PHASE-TRACKING.md
└── CLAUDE.md                     # agent-facing project guide
```

## Harness flow
```
Intake → Evidence sync → Compliance GATE → Score → Devil's-advocate → Synthesize → Gate re-check
```
- The **compliance gate** runs before any scored deliverable: `HALTED` ⇒ no
  deliverable; `FAIL` ⇒ report is labeled **NON-COMPLIANT** with violations.
- Every scored dimension cites a source or states an explicit assumption.
- Degraded (offline) mode is declared honestly; no fabricated live data.

## Quick start
### Run the skill (as an agent harness)
Follow `skills/main.md`: provide manifests + lockfiles, SBOM (optional), CI/CD
config, registries, provenance, and your policy. The harness enforces all gates
and emits the report format defined in `skills/sub-hardening-roadmap.md`.

### Run the deterministic logic directly
```python
import json, supplychain_logic as sc
inv = json.load(open("tests/fixtures/sample_inventory.json"))
vulns = json.load(open("tests/fixtures/sample_vulns.json"))
report = sc.compliance_check(inv, vulns)          # gate status + violations
scoring = sc.score_dimensions(inv, vulns, report) # composite + SLSA + dims
print(scoring["headline"], scoring["slsa_level"])
```

### Refresh the knowledge brain
```bash
python tools/knowledge_updater.py            # uses crawl4ai if installed, else stdlib
python tools/knowledge_updater.py --dry-run  # score + dedupe, no write
```
See `tools/README.md` for the weekly cron / Windows scheduled-task setup.

### Run the tests
```bash
pytest tests/test_harness.py -q               # 41 tests, no network, no model
```

## Disclaimer
This skill provides **informational analysis only** and is not professional
legal, financial, tax or accounting advice. Verify with a licensed professional
before acting. The compliance gate halts and flags (rather than guesses) when a
matter requires qualified legal/compliance counsel.

## License
MIT — see repository headers. Third-party framework names belong to their
respective owners (SLSA, OWASP, SPDX, CycloneDX, FIRST/EPSS, Sigstore, CISA).
