---
name: software-supply-chain-security__sub-vuln-scanner
description: Sub-skill of software-supply-chain-security — Identify known-vulnerable, abandoned, malicious or typosquatted dependencies and rank them by real exploit-likelihood (CVSS × EPSS × reachability), not raw CVSS alone.
---

## Purpose
Given the `InventoryRecord` from intake, populate `vulnerabilities_known` for every dependency and add a `risk_assessment` block: known CVEs, fix-availability, abandonment/maintenance signals, malicious/typosquat signals, and an exploit-likelihood priority. Output is structured; the downstream scoring sub-skill turns it into dimension scores.

## Inputs
- `InventoryRecord` from `sub-inventory-intake`.
- Advisory data from `SECOND-KNOWLEDGE-BRAIN.md` + live sources (graceful degradation when offline).
- Active `policy` (carried inside the record).

## Advisory Sources (in priority/evidence order)
1. **OSV.dev** (`https://api.osv.dev/v1/query`) — unified, cross-ecosystem, machine-readable. Primary.
2. **NVD CVE feeds** (`https://services.nvd.nist.gov/rest/json/cves/2.0`) — CVSS vectors.
3. **GitHub Security Advisories** (`ghsa`) + `audit`/`pip-audit`/`npm audit`/`cargo audit`/`govulncheck` local signals.
4. **EPSS** (`https://api.first.org/data/epss`) — exploit prediction scoring for prioritization.
5. **Vendor/registry security advisories** — npm advisories, PyPA, RustSec, GitHub Advisory Database.
6. **Malware/typosquat intel** — checkmarx, sockets.dev, Snyk advisories, public malware disclosure reports.

> Evidence hierarchy: official advisory/PSA > vendor advisory > curated DB (OSV/NVD) > blog/report. Cite the highest tier used per finding.

## Procedure
1. **Batch query** advisories per `(ecosystem, name, version)` against OSV (and NVD where OSV lacks CVSS). Throttle to registry/provider rate limits (e.g. NVD ≈ 5 req/30s without key). Cache responses for the run.
2. **Normalize each CVE** to: `cve_id, cvss_v3_score, cvss_vector, epss_score, epss_percentile, fixed_versions[], published, severity, advisory_url, evidence_tier`.
3. **Compute exploit-likelihood priority** per finding:
   ```
   priority_raw = cvss_v3_score/10 * 0.45
                 + epss_score * 0.40          # P(exploit in wild)
                 + reachability * 0.15        # 0..1 from static reachability if available, else 0.5 default-assumption
   priority_band = HIGH (>=0.6) | MEDIUM (>=0.3) | LOW (<0.3)
   ```
   Reachability may come from `govulncheck`/`pip-audit --vulnerability-visibility`/`osv-scanner --call-analysis`; when absent, set `reachability=0.5` and tag `assumption: no reachability data`.
4. **Abandonment / maintenance signals** per dependency:
   - `last_published` age > 365 days → `maintenance: stale`
   - > 730 days → `maintenance: abandoned`
   - `publish_count < 3` and `account_age_days < 90` → `maintenance: nascent-risk`
   - maintainer without 2FA / single maintainer on a critical dep → `bus_factor: 1`
5. **Malicious / typosquat heuristics** (score 0..1; flag if ≥0.5):
   - Levenshtein distance ≤2 from a popular package name in same ecosystem.
   - Name contains extra separators/dashes vs canonical (`lodash` vs `lodas`/`lod-ash`).
   - Maintainer account age < 90d **and** package age < 90d.
   - Download spike inconsistent with historical trend (post-publication injection).
   - No source repo / repo mismatched to published package.
   - Listed on a known-malware advisory (sockets.dev, checkmarx, GitHub malware advisories).
   Each signal contributes a weight; the combined `typosquat_risk` is recorded, not just a boolean.
6. **Fix availability** — for each CVE, record `fixed_versions[]` and whether the installed version is in the affected range. Compute `patch_responsiveness_proxy = days_since_published - days_until_fix_available` (lower/negative is better).
7. **Emit** `VulnScanReport` (structured). Do **not** emit prose-only conclusions.

## Output Schema (appended/enriched on `InventoryRecord.dependencies[*]`)
```yaml
vulnerabilities_known:
  - cve_id: CVE-XXXX-XXXX | GHSA-... | OSV-...
    cvss_v3_score: float
    cvss_vector: str
    epss_score: float
    epss_percentile: float
    severity: critical|high|medium|low
    affected_range: str
    fixed_versions: [str]
    fix_available_for_installed: bool
    published: ISO-8601
    advisory_url: url
    evidence_tier: advisory|vendor|curated|report
    reachability: float | null
    reachability_assumption: bool
    priority_raw: float
    priority_band: HIGH|MEDIUM|LOW
risk_assessment:
  maintenance: active|stale|abandoned|nascent-risk
  bus_factor: int
  typosquat_risk: float        # 0..1
  typosquat_signals: [str]
  malicious_advisory_hits: [url]
  patch_responsiveness_proxy: int   # days
```
```yaml
VulnScanReport:
  scanned_at: ISO-8601
  advisory_sources_used: [osv, nvd, ghsa, epss, ...]
  degraded: bool                  # true if any source offline
  summary:
    total_findings: int
    high_priority: int
    medium_priority: int
    low_priority: int
    abandoned_deps: int
    typosquat_flags: int
    no_fix_available: int
  top_priorities: [ {dependency_id, cve_id, priority_band, rationale} ]   # top 10
```

## Evidence & Assumption Rules
- Every CVE must cite an `advisory_url` and `evidence_tier`.
- EPSS missing ⇒ `epss_score=null`, `reachability_assumption=true`, and the priority formula still runs with documented substitution (`epss=0.0`).
- Typosquat signals are heuristics — never assert "malicious"; assert "typosquat_risk=X, review recommended".
- If offline (no advisory source reachable), set `degraded=true`, populate only from `SECOND-KNOWLEDGE-BRAIN.md` cached advisories, and explicitly state no live CVE data.

## Quality Gate
- [ ] Every populated dependency has either CVE findings or an explicit `no_known_vulns_as_of: <date>` marker.
- [ ] At least one advisory source was consulted (or degraded mode clearly declared).
- [ ] Every finding has `priority_band` computed via the documented formula — no CVSS-only ranking.
- [ ] Typosquat risk is a numeric score with listed signals, not a bare boolean.
- [ ] Fix availability stated per finding (including `no_fix`).
- [ ] All `evidence_tier` tags present; assumptions marked.

## Hand-off
Downstream: `sub-compliance-check` (license + policy), `sub-supplychain-scoring` (uses `vulnerabilities_known`, `risk_assessment`, `pipeline`).
