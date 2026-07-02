#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_harness.py - executable validation for the software-supply-chain-security
skill. Requires NO network and NO model. Validates the deterministic logic
encoded in the sub-skills and the knowledge_updater pipeline.

Covers the scenarios declared in tests/test-scenarios.md:
  * priority-band classification (Scenario 1, 9)
  * typosquat risk surfacing (Scenario 2, 10)
  * license classification + compliance gate decision (Scenario 3, 8)
  * SLSA level + missing signals (Scenario 4)
  * OWASP CICD control mapping (Scenario 5)
  * degraded-mode honesty (Scenario 6)
  * insufficient-input / halt paths (Scenario 7, 8)
  * false-positive / assumption challenge (Scenario 9)
  * dependency-confusion trust challenge (Scenario 10)
  * knowledge_updater relevance / recency / dedupe / arxiv parsing
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TOOLS = os.path.join(ROOT, "tools")
sys.path.insert(0, TOOLS)

import supplychain_logic as logic  # noqa: E402
import knowledge_updater as ku  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")


def load_fixture(name: str) -> dict:
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8-sig") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def inventory():
    return load_fixture("sample_inventory.json")


@pytest.fixture(scope="module")
def vulns():
    return load_fixture("sample_vulns.json")


# ---------------------------------------------------------------------------
# Scenario 1 & 9: prioritization by CVSS x EPSS x reachability
# ---------------------------------------------------------------------------
def test_priority_band_high_for_critical_exploitable():
    raw, band, assum = logic.compute_priority(9.8, 0.62, 0.8, False)
    assert band == "HIGH"
    assert raw >= 0.6
    assert assum is False


def test_priority_not_cvss_only():
    # High CVSS but very low EPSS + low reachability should NOT be HIGH band.
    raw, band, _ = logic.compute_priority(9.0, 0.0001, 0.1, False)
    assert band in ("LOW", "MEDIUM")
    assert raw < 0.6


def test_priority_reachability_assumption_marked():
    raw, band, assum = logic.compute_priority(7.5, 0.0012, None, True)
    assert assum is True
    # cvss 7.5 with assumed 0.5 reachability + tiny EPSS -> ~0.41 MEDIUM, not HIGH
    assert band == "MEDIUM"


def test_priority_epss_missing_defaults_zero():
    raw, _, _ = logic.compute_priority(8.0, None, 0.5, False)
    expected = round(0.8 * 0.45 + 0.0 * 0.40 + 0.5 * 0.15, 4)
    assert raw == expected


# ---------------------------------------------------------------------------
# Scenario 2 & 10: typosquat risk surfacing
# ---------------------------------------------------------------------------
def test_typosquat_risk_surfaces_in_scoring(vulns):
    max_risk = max(ra.get("typosquat_risk", 0.0) for ra in vulns["risk_assessments"])
    assert max_risk >= 0.5
    # D2 must be reduced accordingly (D2 = 100*(1-risk))
    assert logic.score_dimensions({}, vulns, logic.ComplianceReport(gate_status="PASS"))["dimensions"]["D2"] <= 15.0


# ---------------------------------------------------------------------------
# Scenario 3 & 8: license classification + compliance gate
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("spdx,expected", [
    ("MIT", "permissive"),
    ("Apache-2.0", "permissive"),
    ("MIT OR Apache-2.0", "permissive"),
    ("GPL-3.0-only", "strong_copyleft"),
    ("AGPL-3.0-only", "network_copyleft"),
    ("LGPL-2.1-only", "weak_copyleft"),
    ("UNKNOWN", "unknown"),
    ("NONE", "none"),
    ("GPL-2.0-only WITH Classpath-exception-2.0", "strong_copyleft"),
])
def test_classify_license(spdx, expected):
    assert logic.classify_license(spdx) == expected


def test_compliance_gate_fail_on_gpl_and_unknown(inventory, vulns):
    report = logic.compliance_check(inventory, vulns)
    # UNKNOWN license (lodas) under require_full_spwd -> blocker -> HALTED
    assert report.gate_status == "HALTED"
    assert any(v.type == "license" and v.severity == "blocker" for v in report.violations)
    assert report.license_summary["unknown"] >= 1


def test_compliance_gate_pass_when_clean():
    inv = {
        "policy": {"allowed_licenses": ["MIT"], "require_full_spdx": True,
                   "require_signature": False},
        "env_context": {},
        "dependencies": [{"id": "x|a|1", "license": "MIT",
                          "signature": {"scheme": "none"}}],
        "pipeline": {"jobs": [], "base_images": []},
    }
    report = logic.compliance_check(inv, {"findings": []})
    assert report.gate_status == "PASS"
    assert report.violations == []


def test_compliance_fail_labels_hard_violations():
    inv = {
        "policy": {"require_full_spdx": False, "allow_strong_copyleft": False,
                   "disallowed_licenses": ["GPL-3.0-only"], "max_cvss_to_allow": 7.0,
                   "require_signature": False},
        "env_context": {},
        "dependencies": [{"id": "x|g|1", "license": "GPL-3.0-only",
                          "signature": {"scheme": "none"}}],
        "pipeline": {"jobs": [], "base_images": []},
    }
    vulns = {"findings": [{"cve_id": "CVE-1", "cvss_v3_score": 9.8,
                           "fix_available_for_installed": True,
                           "fixed_versions": ["2"]}]}
    report = logic.compliance_check(inv, vulns)
    assert report.gate_status == "FAIL"
    assert any(v.severity == "hard" for v in report.violations)


# ---------------------------------------------------------------------------
# Scenario 4: SLSA level + missing signals
# ---------------------------------------------------------------------------
def test_slsa_level_zero_without_signals():
    level, missing = logic.assign_slsa_level([])
    assert level == 0
    assert "provenance_generated" in missing


def test_slsa_level_three_requires_full_set():
    level, missing = logic.assign_slsa_level(logic.SLSA_LEVELS[3])
    assert level == 3
    assert set(missing) == (logic.SLSA_LEVELS[4] - logic.SLSA_LEVELS[3])


def test_slsa_no_partial_credit():
    # missing one L3 signal -> cannot claim L3
    sigs = set(logic.SLSA_LEVELS[3])
    sigs.discard("hermetic_build")
    level, missing = logic.assign_slsa_level(sigs)
    assert level == 2
    assert "hermetic_build" in missing


# ---------------------------------------------------------------------------
# Scenario 5: OWASP CICD control mapping
# ---------------------------------------------------------------------------
def test_owasp_controls_mapping_shape(inventory, vulns):
    report = logic.compliance_check(inventory, vulns)
    sc = logic.score_dimensions(inventory, vulns, report)
    controls = sc["owasp_controls"]
    assert set(controls.keys()) == {"met", "unmet"}
    assert "CICD-SEC-03" in controls["unmet"]  # fixture has unpinned action/image


# ---------------------------------------------------------------------------
# Scenario 6: degraded-mode honesty
# ---------------------------------------------------------------------------
def test_degraded_mode_lowers_confidence(inventory):
    vulns_degraded = {"findings": [], "risk_assessments": [], "degraded": True}
    report = logic.compliance_check(inventory, vulns_degraded)
    sc = logic.score_dimensions(inventory, vulns_degraded, report)
    assert sc["confidence"] <= 0.5 + 0.5 * 0.66 - 0.2


# ---------------------------------------------------------------------------
# Scoring end-to-end shape
# ---------------------------------------------------------------------------
def test_scoring_six_dimensions_and_composite(inventory, vulns):
    report = logic.compliance_check(inventory, vulns)
    sc = logic.score_dimensions(inventory, vulns, report)
    assert set(sc["dimensions"]) == {"D1", "D2", "D3", "D4", "D5", "D6"}
    assert sum(sc["weights"].values()) == pytest.approx(1.0)
    assert 0.0 <= sc["composite"] <= 100.0
    assert 0.0 <= sc["confidence"] <= 1.0
    assert "NON-COMPLIANT" in sc["headline"] or sc["headline"].endswith(report.gate_status)


def test_slsa_missing_signals_reported_in_scoring(inventory, vulns):
    report = logic.compliance_check(inventory, vulns)
    sc = logic.score_dimensions(inventory, vulns, report)
    assert sc["slsa_level"] == 0
    assert isinstance(sc["slsa_missing_signals_for_next_level"], list)


# ---------------------------------------------------------------------------
# Scenario 9: false-positive / assumption challenge
# ---------------------------------------------------------------------------
def test_false_positive_assumption_marked(vulns):
    # The requests finding has affected_range <2.31.0 but installed is 2.31.0
    # => not affected. Reachability is assumed -> must be flagged.
    f = next(x for x in vulns["findings"] if x["cve_id"] == "CVE-2023-32681")
    assert f["reachability_assumption"] is True
    assert f["affected_range"] == "<2.31.0"
    # Even with assumed reachability, EPSS is tiny -> NOT HIGH band (no inflation).
    raw, band, _ = logic.compute_priority(
        f["cvss_v3_score"], f["epss_score"], f["reachability"], f["reachability_assumption"])
    assert band != "HIGH"


# ---------------------------------------------------------------------------
# Scenario 10: dependency-confusion trust challenge
# ---------------------------------------------------------------------------
def test_dependency_confusion_maps_to_cicd_sec_03(inventory, vulns):
    report = logic.compliance_check(inventory, vulns)
    sc = logic.score_dimensions(inventory, vulns, report)
    # Unpinned third-party action + unpinned base image -> CICD-SEC-03 unmet
    assert "CICD-SEC-03" in sc["owasp_controls"]["unmet"]
    assert any(v.policy_ref and "03" in v.policy_ref for v in report.violations)


# ---------------------------------------------------------------------------
# knowledge_updater: pure functions
# ---------------------------------------------------------------------------
def test_source_hash_stable_and_normalized():
    a = ku.source_hash("HTTPS://example.com/A/")
    b = ku.source_hash("https://example.com/a")
    assert a == b
    assert len(a) == 16


def test_source_hash_differs():
    assert ku.source_hash("https://a.com") != ku.source_hash("https://b.com")


def test_relevance_score_basic():
    s = ku.relevance_score("SLSA provenance adoption study", "dependency confusion detection")
    assert s > 0.0
    assert ku.relevance_score("cooking recipes", "") == 0.0


def test_relevance_score_in_range():
    s = ku.relevance_score("supply chain attack", "typosquatting detection SLSA")
    assert 0.0 <= s <= 1.0


def test_recency_weight_decay():
    today = dt.date(2026, 7, 2)
    assert ku.recency_weight("2026-07-02", today) == 1.0
    # exactly 365d is beyond the decay window -> floored at 0.1 for older items
    assert ku.recency_weight("2025-07-02", today) == 0.1
    assert ku.recency_weight("2020-01-01", today) == 0.1
    assert ku.recency_weight("garbage", today) == 0.1


def test_recency_weight_at_half_year():
    today = dt.date(2026, 7, 2)
    assert ku.recency_weight("2026-01-02", today) == pytest.approx(round(1 - 181 / 365, 3))


def test_combined_score_uses_both():
    e = ku.Entry(title="SLSA provenance adoption", authors="-",
                 date=dt.date.today().isoformat(),
                 url="https://example.com/x", abstract="dependency confusion")
    s = ku.combined_score(e)
    assert 0.0 <= s <= 1.0
    assert s > 0.0


def test_existing_hashes_extracts():
    text = "blah <!--hash:abcdef0123456789--> more <!--hash:1111222233334444-->"
    assert ku.existing_hashes(text) == {"abcdef0123456789", "1111222233334444"}


def test_parse_arxiv_atom_tolerates_empty():
    assert ku.parse_arxiv_atom(b"") == []
    assert ku.parse_arxiv_atom(b"not xml") == []


def test_parse_arxiv_atom_parses_entry():
    atom = b'''<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
 <entry>
  <title>Supply Chain Attack Trends</title>
  <summary>Dependency confusion and typosquatting detection.</summary>
  <published>2026-06-20T00:00:00Z</published>
  <id>http://arxiv.org/abs/2606.12345v1</id>
  <link href="http://arxiv.org/abs/2606.12345v1" rel="alternate" type="text/html"/>
  <author><name>Alice</name></author>
  <author><name>Bob</name></author>
 </entry>
</feed>'''
    entries = ku.parse_arxiv_atom(atom)
    assert len(entries) == 1
    e = entries[0]
    assert e.title == "Supply Chain Attack Trends"
    assert "Alice" in e.authors and "Bob" in e.authors
    assert e.date == "2026-06-20"
    assert e.url == "http://arxiv.org/abs/2606.12345v1"


# ---------------------------------------------------------------------------
# knowledge_updater: append dedupe + idempotency (filesystem)
# ---------------------------------------------------------------------------
def test_append_entries_dedup_and_dry_run(tmp_path):
    brain = tmp_path / "BRAIN.md"
    brain.write_text("# Brain\n\n## Core\nseed\n", encoding="utf-8")
    e = ku.Entry(title="SLSA provenance adoption guide", authors="-",
                 date=dt.date.today().isoformat(),
                 url="https://slsa.dev/spec/v1.0", abstract="provenance adoption",
                 venue="slsa.dev", source="domain")
    cfg = ku.RunConfig(brain_path=str(brain), use_crawl4ai=False,
                       use_urllib_fallback=False, dry_run=True, min_relevance=0.0)
    n1 = ku.append_entries([e], cfg)
    assert n1 == 1
    # dry run must not write
    assert "### [" not in brain.read_text(encoding="utf-8")
    cfg.dry_run = False
    n2 = ku.append_entries([e], cfg)
    assert n2 == 1
    text = brain.read_text(encoding="utf-8")
    assert "### [" in text
    assert "<!--hash:" in text
    # idempotent re-run: deduped -> 0 new
    n3 = ku.append_entries([e], cfg)
    assert n3 == 0


def test_append_entries_filters_low_relevance(tmp_path):
    brain = tmp_path / "BRAIN.md"
    brain.write_text("# Brain\n", encoding="utf-8")
    e = ku.Entry(title="cooking recipe of the day", authors="-",
                 date=dt.date.today().isoformat(),
                 url="https://example.com/cook", abstract="pasta and sauce",
                 venue="blog", source="domain")
    cfg = ku.RunConfig(brain_path=str(brain), use_crawl4ai=False,
                       use_urllib_fallback=False, dry_run=False, min_relevance=0.5)
    assert ku.append_entries([e], cfg) == 0


def test_append_entries_missing_brain(tmp_path):
    cfg = ku.RunConfig(brain_path=str(tmp_path / "nope.md"), use_crawl4ai=False,
                       use_urllib_fallback=False)
    assert ku.append_entries([], cfg) == 0


# ---------------------------------------------------------------------------
# CLI smoke (argparse only, no network)
# ---------------------------------------------------------------------------
def test_cli_arg_parser_defaults():
    p = ku.build_arg_parser()
    args = p.parse_args([])
    assert args.no_crawl4ai is False
    assert args.dry_run is False
    assert args.max_entries == 25


def test_cli_save_config_writes_file(tmp_path):
    cfg_path = tmp_path / "cfg.json"
    rc = ku.main(["--config", str(cfg_path), "--save-config", "--no-crawl4ai"])
    assert rc == 0
    assert cfg_path.exists()
    import json
    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert data["use_crawl4ai"] is False
