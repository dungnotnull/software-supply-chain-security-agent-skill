---
name: software-supply-chain-security__sub-compliance-check
description: Sub-skill of software-supply-chain-security — Check license compliance and policy violations across the dependency tree and enforce the compliance GATE before any scored deliverable is emitted.
---

## Purpose
This is the **compliance gate** of the harness. Before scoring or synthesis, it verifies that the dependency tree, pipeline and provenance posture satisfy the organization's `policy` and any applicable regulatory/disclosure obligations. If a hard requirement is unmet or genuinely ambiguous in a way that could constitute unlicensed professional/legal advice, the sub-skill **halts and flags** instead of producing advisory output. It never emits legal opinions.

## Inputs
- `InventoryRecord` (with `policy`, `dependencies[].license`, `pipeline`, `env_context`).
- `VulnScanReport` (for policy limits tied to CVSS/EPSS).
- `SECOND-KNOWLEDGE-BRAIN.md` license + regulatory reference tables.

## Compliance Dimensions Checked

### 1. License compliance (per dependency and aggregate)
Classify each SPDX expression against the policy allow/deny lists.

| Category | Treatment |
|----------|-----------|
| Permissive (MIT, Apache-2.0, BSD-2/3, ISC, 0BSD) | allowed by default |
| Weak copyleft (LGPL-2.1+, MPL-2.0, EPL-2.0) | allowed if `allow_weak_copyleft=true` AND linkage reviewed |
| Strong copyleft (GPL-2.0, GPL-3.0, AGPL-3.0) | **deny** unless `allow_strong_copyleft=true` (flag) |
| Network copyleft (AGPL-3.0, SSPL-1.0) | **deny** for SaaS/network services unless explicitly approved |
| Proprietary / `UNLICENSED` / `UNKNOWN` / `NONE` | **blocker** — must be resolved before gate pass |
| Dual/triple license (e.g. `MIT OR Apache-2.0`) | take the most permissive applicable; record choice + rationale |
| License-with-exception (`GPL-2.0-only WITH Classpath-exception-2.0`) | evaluate the exception effect explicitly |

Policy fields consumed:
- `allowed_licenses`, `disallowed_licenses`, `allow_weak_copyleft`, `allow_strong_copyleft`, `require_full_spdx` (reject `UNKNOWN`/`NONE`).

### 2. Vulnerability policy limits
- `max_cvss_to_allow`: any installed dependency with a known CVE above the threshold AND `fix_available_for_installed=true` is a **hard violation**.
- `block_high_epss`: if set, EPSS percentile ≥ threshold on a fixable CVE ⇒ hard violation.
- `require_no_critical_in_prod`: critical CVEs in production-scoped deps ⇒ hard violation.

### 3. Provenance / signing policy
- `require_signature=true` ⇒ unsigned artifacts in the trust boundary are violations.
- `required_slsa_level` ⇒ provisional finding (final SLSA level assigned by scoring), but a missing provenance attestation below the required level is recorded as a policy violation to surface.

### 4. Pipeline policy
- Third-party actions/plugins not pinned to a SHA ⇒ violation.
- Base images not pinned to a digest ⇒ violation.
- Secrets printed in logs / no OIDC for cloud auth ⇒ violation.

### 5. Regulatory context (informational mapping, NOT legal advice)
If `env_context.regulatory` is set, map to known framework **obligations** as informational flags only:
- **PCI-DSS** → requirement 6 (secure software, patching SLAs); flag unpatched critical CVEs.
- **HIPAA** → Security Rule §164.308(a)(1) risk analysis; flag undocumented critical vulns.
- **FedRAMP / SOC 2** → change/patch management controls; flag untracked deps.
- **EU CRA (Cyber Resilience Act)** → vulnerability & SBOM disclosure duties; flag missing SBOM.
- **Executive Order 14028 (US)** → SBOM + provenance expectations; flag missing SBOM/provenance.

> The sub-skill records that these obligations *appear applicable* and recommends confirmation by qualified counsel/auditor. It does **not** render a compliance attestation.

## Procedure
1. **Build a violation list** traversing every dependency, the pipeline block and the regulatory mapping. Each violation: `{id, type, severity: blocker|hard|soft, entity, evidence, policy_ref, recommended_action}`.
2. **Classify severity:**
   - `blocker` — analysis cannot proceed (e.g. `UNKNOWN`/`NONE` license with `require_full_spdx`, missing required input).
   - `hard` — a policy rule is violated; output may be produced but the gate status is FAIL with the violations listed.
   - `soft` — deviation from best practice; warn but do not fail.
3. **Decision logic:**
   - Any `blocker` ⇒ `gate_status = HALTED`, return violations, do NOT produce a scored deliverable. Re-prompt for the missing/ambiguous item.
   - `hard` violations present ⇒ `gate_status = FAIL`. The harness may still produce a scored report **but it must be labeled "NON-COMPLIANT — policy violations present"** at the top, with the violations enumerated. No gate-bypass path.
   - No `hard`/`blocker` ⇒ `gate_status = PASS`.
4. **Halt-and-flag for professional-scope ambiguity:** if resolving a violation would require interpreting a license's legal effect or rendering a regulatory compliance opinion, the sub-skill **halts**, states "This requires qualified legal/compliance counsel," and returns the unresolved item. It does not guess.
5. **Emit** `ComplianceReport` (structured).

## Output Schema
```yaml
ComplianceReport:
  checked_at: ISO-8601
  gate_status: PASS | FAIL | HALTED
  policy_version: str
  violations:
    - id: str
      type: license|vuln_policy|provenance|pipeline|regulatory
      severity: blocker|hard|soft
      entity: dependency_id | job_name | base_image
      evidence: str
      policy_ref: str
      recommended_action: str
  license_summary:
    by_category: { permissive: n, weak_copyleft: n, strong_copyleft: n, network_copyleft: n, unknown: n }
    full_spdx_coverage_pct: float
  regulatory_flags: [ {framework, obligation, status: applicable|not_applicable|unknown, note} ]
  professional_scope_halt: [ {item, reason} ]   # populated when legal/compliance counsel needed
  degraded: bool
```

## Evidence & Assumption Rules
- License classifications cite the SPDX license list (`https://spdx.org/licenses/`).
- Regulatory mappings cite the official source (PCI SSC, HHS, NIST, EUR-Lex, whitehouse.gov EO text) and are labeled **informational**.
- `UNKNOWN`/`NONE` is never silently treated as permissive.

## Quality Gate
- [ ] Every dependency's license classified or marked `UNKNOWN` (no silent default).
- [ ] Violation severities assigned; decision logic applied exactly.
- [ ] No `HALTED`/`FAIL` path is bypassed to produce a clean-looking deliverable.
- [ ] Professional-scope ambiguities halt and flag instead of guessing.
- [ ] Regulatory items labeled informational, with a "confirm with counsel" note.
- [ ] `ComplianceReport` emitted and consumed by scoring before synthesis.

## Hand-off
Downstream: `sub-supplychain-scoring` uses `gate_status` and `violations`; `main.md` blocks synthesis if `gate_status == HALTED` and labels output NON-COMPLIANT if `FAIL`.
