#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
supplychain_logic.py - reference implementation of the deterministic logic
encoded in the `software-supply-chain-security` sub-skills.

This module codifies the *machine-checkable* parts of the skill harness so they
can be unit-tested and reused by sibling skills in the software-devops cluster
(see INTEGRATION.md):

  * license classification (SPDX categories)
  * compliance gate decision logic (PASS / FAIL / HALTED)
  * vulnerability prioritization (CVSS x EPSS x reachability -> band)
  * SLSA level assignment (build track L0-L4)
  * six-dimension scoring + disclosed-weight composite + confidence

It contains pure functions with no network/model dependencies. The narrative
sub-skill markdown remains the authoritative spec; this code is the executable
mirror of that spec.
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD",
              "BSL-1.0", "Unlicense", "Zlib"}
WEAK_COPYLEFT = {"LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only",
                 "LGPL-3.0-or-later", "MPL-2.0", "EPL-2.0", "EPL-1.0",
                 "CDDL-1.0", "CDDL-1.1"}
STRONG_COPYLEFT = {"GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only",
                   "GPL-3.0-or-later", "GPL-2.0-with-classpath-exception-2.0"}
NETWORK_COPYLEFT = {"AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0",
                    "BUSL-1.1", "CPAL-1.0"}
NONE_LIKE = {"NONE", "NOASSERTION", "", None, "UNKNOWN", "UNLICENSED"}

OWASP_CICD_CONTROLS = [
    "CICD-SEC-01", "CICD-SEC-02", "CICD-SEC-03", "CICD-SEC-04", "CICD-SEC-05",
    "CICD-SEC-06", "CICD-SEC-07", "CICD-SEC-08", "CICD-SEC-09", "CICD-SEC-10",
]
DEFAULT_WEIGHTS = {"D1": 0.25, "D2": 0.15, "D3": 0.15, "D4": 0.20, "D5": 0.15, "D6": 0.10}

SLSA_LEVELS = {
    1: {"provenance_generated"},
    2: {"provenance_generated", "managed_build", "version_controlled_source", "tamper_resistant_provenance"},
    3: {"provenance_generated", "managed_build", "version_controlled_source",
        "tamper_resistant_provenance", "isolated_build", "hermetic_build", "two_party_review"},
    4: {"provenance_generated", "managed_build", "version_controlled_source",
        "tamper_resistant_provenance", "isolated_build", "hermetic_build", "two_party_review",
        "reproducible_build", "non_falsifiable_provenance"},
}


def classify_license(spdx: Optional[str]) -> str:
    """Return one of: permissive, weak_copyleft, strong_copyleft,
    network_copyleft, unknown, none."""
    if spdx is None:
        return "none"
    expr = spdx.strip()
    if expr in NONE_LIKE:
        return "none" if expr in {"NONE", "NOASSERTION", "", None} else "unknown"
    norm = expr
    # Handle dual/triple license expressions: take the most permissive branch.
    for branch in re.split(r"\s+OR\s+", norm):
        b = branch.strip().split(" WITH ")[0].strip()
        if b in NETWORK_COPYLEFT:
            continue
        if b in STRONG_COPYLEFT:
            continue
        if b in WEAK_COPYLEFT:
            continue
        if b in PERMISSIVE:
            return "permissive"
    # No permissive branch; classify the dominant category
    for branch in re.split(r"\s+OR\s+", norm):
        b = branch.strip().split(" WITH ")[0].strip()
        if b in NETWORK_COPYLEFT:
            return "network_copyleft"
        if b in STRONG_COPYLEFT:
            return "strong_copyleft"
        if b in WEAK_COPYLEFT:
            return "weak_copyleft"
    if any(b in PERMISSIVE for b in re.split(r"\s+OR\s+", norm)):
        return "permissive"
    return "unknown"


@dataclass
class Violation:
    id: str
    type: str
    severity: str  # blocker | hard | soft
    entity: str
    evidence: str
    policy_ref: str
    recommended_action: str


@dataclass
class ComplianceReport:
    gate_status: str  # PASS | FAIL | HALTED
    violations: list = field(default_factory=list)
    license_summary: dict = field(default_factory=dict)
    regulatory_flags: list = field(default_factory=list)
    professional_scope_halt: list = field(default_factory=list)
    degraded: bool = False


def compliance_check(inventory: dict, vulns: dict) -> ComplianceReport:
    """Implement the sub-compliance-check decision logic."""
    policy = inventory.get("policy", {})
    deps = inventory.get("dependencies", [])
    env = inventory.get("env_context", {})
    report = ComplianceReport(gate_status="PASS")

    by_cat = {"permissive": 0, "weak_copyleft": 0, "strong_copyleft": 0,
              "network_copyleft": 0, "unknown": 0}
    require_full = policy.get("require_full_spdx", False)
    allow_strong = policy.get("allow_strong_copyleft", False)
    allow_weak = policy.get("allow_weak_copyleft", False)
    disallowed = set(policy.get("disallowed_licenses", []))

    for dep in deps:
        cat = classify_license(dep.get("license"))
        by_cat[cat] = by_cat.get(cat, 0) + 1
        lic = (dep.get("license") or "").strip()
        if cat in ("none", "unknown") and require_full:
            report.violations.append(Violation(
                id=f"V-LIC-{dep['id']}", type="license", severity="blocker",
                entity=dep["id"], evidence=f"license={lic!r}",
                policy_ref="require_full_spdx",
                recommended_action="Resolve full SPDX license or remove dependency."))
        elif cat == "network_copyleft":
            sev = "hard" if not allow_strong else "soft"
            report.violations.append(Violation(
                id=f"V-LIC-{dep['id']}", type="license", severity=sev,
                entity=dep["id"], evidence=f"network copyleft {lic}",
                policy_ref="disallowed_licenses/network_copyleft",
                recommended_action="Replace or obtain explicit approval for SaaS use."))
        elif cat == "strong_copyleft":
            sev = "hard" if not allow_strong else "soft"
            report.violations.append(Violation(
                id=f"V-LIC-{dep['id']}", type="license", severity=sev,
                entity=dep["id"], evidence=f"strong copyleft {lic}",
                policy_ref="allow_strong_copyleft",
                recommended_action="Replace or allowlist explicitly."))
        elif cat == "weak_copyleft" and not allow_weak:
            report.violations.append(Violation(
                id=f"V-LIC-{dep['id']}", type="license", severity="soft",
                entity=dep["id"], evidence=f"weak copyleft {lic}",
                policy_ref="allow_weak_copyleft",
                recommended_action="Review linkage or enable weak copyleft policy."))
        if lic in disallowed:
            report.violations.append(Violation(
                id=f"V-DIS-{dep['id']}", type="license", severity="hard",
                entity=dep["id"], evidence=f"explicitly disallowed {lic}",
                policy_ref="disallowed_licenses",
                recommended_action="Remove dependency."))

    # Vulnerability policy limits
    max_cvss = policy.get("max_cvss_to_allow")
    for f in vulns.get("findings", []):
        if f.get("fix_available_for_installed") and max_cvss is not None:
            if f.get("cvss_v3_score", 0) > max_cvss:
                report.violations.append(Violation(
                    id=f"V-VUL-{f['cve_id']}", type="vuln_policy", severity="hard",
                    entity=f.get("dependency_id", ""), evidence=(
                        f"{f['cve_id']} cvss={f.get('cvss_v3_score')} > {max_cvss}, fixable"),
                    policy_ref="max_cvss_to_allow",
                    recommended_action=f"Upgrade to {f.get('fixed_versions', [])}."))

    # Pipeline policy
    pipe = inventory.get("pipeline", {})
    for job in pipe.get("jobs", []):
        if job.get("uses_third_party_actions") and not job.get("pinned_to_sha"):
            report.violations.append(Violation(
                id=f"V-PIPE-{job['name']}", type="pipeline", severity="hard",
                entity=job["name"], evidence="third-party action not pinned to SHA",
                policy_ref="CICD-SEC-01/03",
                recommended_action="Pin action to a commit SHA."))
    for img in pipe.get("base_images", []):
        if not img.get("is_pinned"):
            report.violations.append(Violation(
                id=f"V-IMG-{img['image']}", type="pipeline", severity="soft",
                entity=img["image"], evidence="base image not pinned to digest",
                policy_ref="CICD-SEC-08/10",
                recommended_action="Pin base image to an immutable digest."))
    if policy.get("require_signature"):
        for dep in deps:
            sig = dep.get("signature", {})
            if sig.get("scheme") in (None, "none"):
                report.violations.append(Violation(
                    id=f"V-SIG-{dep['id']}", type="provenance", severity="soft",
                    entity=dep["id"], evidence="no signature",
                    policy_ref="require_signature",
                    recommended_action="Adopt Sigstore/cosign signing."))

    # Regulatory informational flags (NOT legal advice)
    reg = env.get("regulatory", [])
    if reg:
        for fw in reg:
            report.regulatory_flags.append({
                "framework": fw, "status": "applicable",
                "note": "Informational mapping only; confirm with qualified counsel/auditor."})

    report.license_summary = by_cat

    # Decision logic
    has_blocker = any(v.severity == "blocker" for v in report.violations)
    has_hard = any(v.severity == "hard" for v in report.violations)
    # Professional-scope halt: an UNKNOWN/none license with no policy resolution
    # AND a regulatory context that would require a legal interpretation.
    if require_full and by_cat.get("unknown", 0) > 0 and reg:
        report.professional_scope_halt.append({
            "item": "UNKNOWN license under regulatory context",
            "reason": "Resolving license legal effect requires qualified counsel."})
    if report.professional_scope_halt or has_blocker:
        report.gate_status = "HALTED"
    elif has_hard:
        report.gate_status = "FAIL"
    else:
        report.gate_status = "PASS"
    return report


def compute_priority(cvss: float, epss: Optional[float], reachability: Optional[float],
                     reachability_assumption: bool = False) -> tuple:
    """CVSS x EPSS x reachability -> (priority_raw, priority_band).

    Reachability defaults to 0.5 (assumption) when unknown. EPSS defaults to 0.0
    when missing. The substitution is documented via reachability_assumption.
    """
    epss = 0.0 if epss is None else float(epss)
    if reachability is None:
        reachability = 0.5
        reachability_assumption = True
    raw = (cvss / 10.0) * 0.45 + epss * 0.40 + float(reachability) * 0.15
    raw = round(min(1.0, max(0.0, raw)), 4)
    if raw >= 0.6:
        band = "HIGH"
    elif raw >= 0.3:
        band = "MEDIUM"
    else:
        band = "LOW"
    return raw, band, reachability_assumption


def assign_slsa_level(signals: Iterable) -> tuple:
    """Return (level, missing_for_next_level) for the build track.

    signals is a set/list of provenance signal strings. The lowest level whose
    full requirement set is satisfied is assigned (no partial credit up).
    """
    sig = set(signals or [])
    level = 0
    for lvl in (4, 3, 2, 1):
        if SLSA_LEVELS[lvl].issubset(sig):
            level = lvl
            break
    missing = []
    if level < 4:
        missing = sorted(SLSA_LEVELS[level + 1] - sig)
    return level, missing


def _owasp_controls_met(pipeline: dict, vulns: dict, inventory: dict) -> dict:
    """Best-effort mapping of pipeline/posture signals to OWASP CICD controls."""
    pipe = pipeline or {}
    met, unmet = [], []
    jobs = pipe.get("jobs", [])
    base_images = pipe.get("base_images", [])
    secrets = pipe.get("secrets_handling", {})
    has_branch_protection = all(j.get("pinned_to_sha") for j in jobs)  # proxy
    has_oidc = secrets.get("oidc_used", False)
    has_masked = secrets.get("masked_in_logs", False)
    has_vault = secrets.get("vault_used", False)
    images_pinned = all(i.get("is_pinned") for i in base_images) if base_images else False
    actions_pinned = all(j.get("pinned_to_sha") for j in jobs) if jobs else False
    two_factor = all(d.get("maintainer", {}).get("has_2fa") for d in inventory.get("dependencies", []))

    checks = {
        "CICD-SEC-01": has_branch_protection,
        "CICD-SEC-02": actions_pinned,            # no poisoned pipeline from PR inputs (proxy)
        "CICD-SEC-03": actions_pinned and images_pinned,  # dependency confusion: pinning
        "CICD-SEC-04": has_oidc,
        "CICD-SEC-05": has_masked and (has_vault or has_oidc),
        "CICD-SEC-06": two_factor,
        "CICD-SEC-07": False,  # webhook validation not represented in fixture
        "CICD-SEC-08": images_pinned,
        "CICD-SEC-09": two_factor,
        "CICD-SEC-10": images_pinned,
    }
    for cid in OWASP_CICD_CONTROLS:
        (met if checks.get(cid) else unmet).append(cid)
    return {"met": met, "unmet": unmet}


def score_dimensions(inventory: dict, vulns: dict, compliance: ComplianceReport,
                     weights: Optional[dict] = None) -> dict:
    """Implement the sub-supplychain-scoring six-dimension model."""
    weights = weights or DEFAULT_WEIGHTS
    deps = inventory.get("dependencies", [])
    n_deps = max(1, len(deps))
    findings = vulns.get("findings", [])
    policy = inventory.get("policy", {})
    coverage = inventory.get("coverage", {})
    target_slsa = policy.get("required_slsa_level", 3)

    # D1 known-vulnerability exposure
    band_weight = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3}
    penalty = 0.0
    for f in findings:
        raw, band, _ = compute_priority(
            f.get("cvss_v3_score", 0), f.get("epss_score"),
            f.get("reachability"), f.get("reachability_assumption", False))
        penalty += raw * band_weight[band]
    normalized = penalty / n_deps
    D1 = max(0.0, min(100.0, 100.0 * (1.0 - normalized)))

    # D2 malicious / typosquat
    max_risk = 0.0
    for ra in vulns.get("risk_assessments", []):
        max_risk = max(max_risk, ra.get("typosquat_risk", 0.0))
        if ra.get("malicious_advisory_hits"):
            max_risk = min(1.0, max_risk + 0.2)
    D2 = max(0.0, min(100.0, 100.0 * (1.0 - max_risk)))

    # D3 license compliance
    base = 100.0
    ls = compliance.license_summary
    base -= 25 * ls.get("strong_copyleft", 0)
    base -= 40 * ls.get("network_copyleft", 0)
    base -= 40 * ls.get("unknown", 0)
    base -= 40 * ls.get("none", 0)
    base -= 10 * ls.get("weak_copyleft", 0)
    D3 = max(0.0, min(100.0, base))
    if compliance.gate_status == "FAIL":
        D3 = min(D3, 40.0)

    # D4 provenance / SLSA
    all_signals = set()
    for d in deps:
        all_signals |= set(d.get("provenance_signals", {}).get("slsa_signals", []) or [])
    slsa_level, missing = assign_slsa_level(all_signals)
    D4 = max(0.0, min(100.0, 100.0 * slsa_level / max(1, target_slsa)))

    # D5 pipeline hardening (OWASP CICD Top 10)
    controls = _owasp_controls_met(inventory.get("pipeline", {}), vulns, inventory)
    hard_penalty = 20 * sum(1 for v in compliance.violations if v.type == "pipeline" and v.severity == "hard")
    soft_penalty = 8 * sum(1 for v in compliance.violations if v.type == "pipeline" and v.severity == "soft")
    controls_met = len(controls["met"])
    D5 = 100.0 - hard_penalty - soft_penalty + max(0, controls_met - 5) * 2 - (10 - controls_met) * 10
    D5 = max(0.0, min(100.0, D5))

    # D6 patch responsiveness
    lag = 0
    k = 0.5
    for f in findings:
        if f.get("fix_available_for_installed"):
            pub = dt.date.fromisoformat((f.get("published") or "2026-07-02")[:10])
            today = dt.date(2026, 7, 2)
            lag += max(0, (today - pub).days)
    D6 = 100.0 - lag * k
    for ra in vulns.get("risk_assessments", []):
        if ra.get("maintenance") == "abandoned":
            D6 -= 15
    D6 = max(0.0, min(100.0, D6))

    dims = {
        "D1": round(D1, 2), "D2": round(D2, 2), "D3": round(D3, 2),
        "D4": round(D4, 2), "D5": round(D5, 2), "D6": round(D6, 2),
    }
    composite = round(sum(weights[d] * dims[d] for d in dims), 2)
    pct_enriched = coverage.get("percent_dependencies_enriched", 0.0)
    confidence = 0.5 + 0.5 * pct_enriched
    if vulns.get("degraded"):
        confidence -= 0.2
    confidence = max(0.0, min(1.0, round(confidence, 3)))

    headline = (f"Composite {composite}/100 (confidence {confidence}) "
                f"- {'NON-COMPLIANT' if compliance.gate_status == 'FAIL' else compliance.gate_status}")
    return {
        "weights": weights, "dimensions": dims, "composite": composite,
        "confidence": confidence, "slsa_level": slsa_level,
        "slsa_missing_signals_for_next_level": missing,
        "owasp_controls": controls, "headline": headline,
    }
