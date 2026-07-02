#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
knowledge_updater.py - self-improving knowledge pipeline for the
`software-supply-chain-security` skill (idea #207).

Pipeline:
  1. Source discovery  - ArXiv (cs.CR, cs.SE) RSS + authoritative domain pages.
  2. Fetch            - crawl4ai AsyncWebCrawler when available, else a stdlib
                        urllib fallback (no third-party deps required to run).
  3. Parse            - title, authors, date, URL/DOI, abstract/summary.
  4. Score            - recency x domain-keyword relevance (0..1).
  5. Dedupe           - sha256(source_url) hash check against the brain.
  6. Append           - date-stamped entries into SECOND-KNOWLEDGE-BRAIN.md.

Design goals:
  * Production-grade, open-source ready: typed, logged, configurable, testable,
    dependency-light. Runs offline (degraded) without crawl4ai.
  * Never crashes the skill: on any fetch/parse error it logs and exits 0 so the
    existing knowledge brain keeps the skill operational.
  * Idempotent append: re-running the same week does not duplicate entries.

Recommended schedule: weekly cron (see tools/README.md).
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Iterable, Optional

LOG = logging.getLogger("knowledge_updater")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_BRAIN = os.path.join(ROOT, "SECOND-KNOWLEDGE-BRAIN.md")
DEFAULT_CONFIG = os.path.join(HERE, "knowledge_updater.config.json")

ARXIV_CATEGORIES = ["cs.CR", "cs.SE"]
DOMAIN_SOURCES = [
    "https://slsa.dev/",
    "https://owasp.org/",
    "https://osv.dev/",
    "https://www.sigstore.dev/",
    "https://www.cisa.gov/",
]
SEARCH_QUERIES = [
    "software supply chain attack trends 2026",
    "dependency confusion typosquatting detection",
    "SLSA provenance adoption",
    "EPSS exploit prediction vulnerability prioritization",
]
RELEVANCE_KEYWORDS = SEARCH_QUERIES

USER_AGENT = "software-supply-chain-security-knowledge-updater/1.0 (+https://slsa.dev)"
HTTP_TIMEOUT = 30.0
MIN_RELEVANCE = 0.05
HASH_RE = re.compile(r"<!--hash:([0-9a-f]{16})-->")
ARXIV_ID_RE = re.compile(r"(arXiv:\d{4}\.\d{4,5}|arXiv:\w{2,4}/\d{7})")


@dataclass(frozen=True)
class Entry:
    title: str
    authors: str
    date: str
    url: str
    abstract: str = ""
    venue: str = ""
    source: str = ""

    def source_hash(self) -> str:
        return source_hash(self.url)


@dataclass
class RunConfig:
    brain_path: str = DEFAULT_BRAIN
    categories: list = dataclasses.field(default_factory=lambda: list(ARXIV_CATEGORIES))
    domain_sources: list = dataclasses.field(default_factory=lambda: list(DOMAIN_SOURCES))
    queries: list = dataclasses.field(default_factory=lambda: list(SEARCH_QUERIES))
    min_relevance: float = MIN_RELEVANCE
    use_crawl4ai: bool = True
    use_urllib_fallback: bool = True
    max_entries_per_source: int = 25
    dry_run: bool = False
    log_level: str = "INFO"


def source_hash(url: str) -> str:
    norm = url.strip().lower()
    if norm.startswith("http://"):
        norm = "https://" + norm[len("http://"):]
    norm = norm.rstrip("/")
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


def relevance_score(title: str, abstract: str, keywords: Iterable = RELEVANCE_KEYWORDS) -> float:
    blob = (title + " " + abstract).lower()
    words = [w for kw in keywords for w in kw.lower().split() if len(w) > 2]
    if not words:
        return 0.0
    hits = sum(1 for w in words if w in blob)
    return round(min(1.0, hits / len(words)), 3)


def recency_weight(date_str: str, today: Optional[dt.date] = None) -> float:
    try:
        d = dt.date.fromisoformat(date_str[:10])
    except (ValueError, TypeError):
        return 0.1
    today = today or dt.date.today()
    age = max(0, (today - d).days)
    if age >= 365:
        return 0.1
    return round(1.0 - (age / 365.0), 3)


def combined_score(entry: Entry, today: Optional[dt.date] = None) -> float:
    rel = relevance_score(entry.title, entry.abstract)
    rec = recency_weight(entry.date, today)
    return round(rel * 0.6 + rec * 0.4, 3)


def existing_hashes(text: str) -> set:
    return set(HASH_RE.findall(text))


def parse_arxiv_atom(xml_bytes: bytes) -> list:
    entries = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        LOG.warning("arxiv atom parse failed: %s", exc)
        return entries
    ns = {"a": "http://www.w3.org/2005/Atom"}
    for node in root.findall("a:entry", ns):
        try:
            title = (node.findtext("a:title", default="", namespaces=ns) or "").strip()
            summary = (node.findtext("a:summary", default="", namespaces=ns) or "").strip()
            published = (node.findtext("a:published", default="", namespaces=ns) or "")[:10]
            url = ""
            for link in node.findall("a:link", ns):
                if link.get("type") == "text/html" or link.get("rel") == "alternate":
                    url = link.get("href", "")
                    break
            if not url:
                id_el = node.find("a:id", ns)
                url = id_el.text.strip() if id_el is not None and id_el.text else ""
            author_names = [
                (a.findtext("a:name", default="", namespaces=ns) or "").strip()
                for a in node.findall("a:author", ns)
            ]
            authors = ", ".join([a for a in author_names if a])[:200] or "-"
            if not title:
                continue
            entries.append(
                Entry(
                    title=re.sub(r"\s+", " ", title),
                    authors=authors,
                    date=published or dt.date.today().isoformat(),
                    url=url,
                    abstract=re.sub(r"\s+", " ", summary)[:1000],
                    venue="arXiv",
                    source="arxiv",
                )
            )
        except Exception as exc:
            LOG.debug("skipping malformed arxiv entry: %s", exc)
            continue
    return entries


def _urllib_get(url: str, timeout: float = HTTP_TIMEOUT) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_arxiv_via_urllib(categories: Iterable, max_per_cat: int) -> list:
    out = []
    for cat in categories:
        url = (
            "http://export.arxiv.org/api/query?search_query=cat:" + cat +
            "&start=0&max_results=" + str(max_per_cat) +
            "&sortBy=submittedDate&sortOrder=descending"
        )
        try:
            data = _urllib_get(url)
            parsed = parse_arxiv_atom(data)
            out.extend(parsed)
            LOG.info("arxiv[%s]: parsed %d entries (urllib)", cat, len(parsed))
        except urllib.error.URLError as exc:
            LOG.warning("arxiv[%s] urllib fetch failed: %s", cat, exc)
    return out


async def _crawl4ai_fetch(urls: list) -> dict:
    try:
        from crawl4ai import AsyncWebCrawler
    except Exception as exc:
        LOG.info("crawl4ai unavailable (%s); will use urllib fallback", exc)
        return {}
    pages = {}
    try:
        async with AsyncWebCrawler(verbose=False) as crawler:
            for url in urls:
                try:
                    res = await crawler.arun(url=url)
                    pages[url] = getattr(res, "markdown", "") or ""
                except Exception as exc:
                    LOG.warning("crawl4ai fetch failed for %s: %s", url, exc)
    except Exception as exc:
        LOG.warning("crawl4ai session error: %s", exc)
    return pages


def _summarize_page(markdown: str, max_chars: int = 1000) -> str:
    text = re.sub(r"```.*?```", " ", markdown, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_chars]


async def collect_entries(cfg: RunConfig) -> list:
    entries = []
    today = dt.date.today().isoformat()

    arxiv_entries = fetch_arxiv_via_urllib(cfg.categories, cfg.max_entries_per_source)
    if not arxiv_entries and cfg.use_crawl4ai:
        pages = await _crawl4ai_fetch(
            [f"https://arxiv.org/list/{c}/recent" for c in cfg.categories]
        )
        for cat, page in pages.items():
            for m in ARXIV_ID_RE.finditer(page):
                aid = m.group(1).split(":")[1]
                entries.append(
                    Entry(
                        title=aid,
                        authors="-",
                        date=today,
                        url=f"https://arxiv.org/abs/{aid}",
                        abstract="",
                        venue="arXiv",
                        source="arxiv",
                    )
                )
    entries.extend(arxiv_entries)

    urls = list(cfg.domain_sources)
    pages = {}
    if cfg.use_crawl4ai:
        pages.update(await _crawl4ai_fetch(urls))
    if cfg.use_urllib_fallback:
        for url in urls:
            if url in pages and pages[url]:
                continue
            try:
                raw = _urllib_get(url)
                pages[url] = raw.decode("utf-8", errors="replace")
            except Exception as exc:
                LOG.warning("urllib fetch failed for %s: %s", url, exc)
    for url, content in pages.items():
        if not content:
            continue
        summary = _summarize_page(content)
        host = urllib.parse.urlparse(url).netloc or url
        entries.append(
            Entry(
                title=f"Update from {host}",
                authors="-",
                date=today,
                url=url,
                abstract=summary,
                venue=host,
                source="domain",
            )
        )

    return entries


def render_entry(entry: Entry, today: dt.date, score: float) -> str:
    h = entry.source_hash()
    finding = (entry.abstract or "").strip().replace("\n", " ")[:280]
    return (
        f"\n### [{today.isoformat()}] {entry.title}\n"
        f"- Authors: {entry.authors}\n"
        f"- Venue/Source: {entry.venue or entry.url}\n"
        f"- Link: {entry.url}\n"
        f"- Key finding: {finding}\n"
        f"- Relevance score: {score}\n"
        f"<!--hash:{h}-->\n"
    )


def append_entries(entries: list, cfg: RunConfig) -> int:
    if not os.path.exists(cfg.brain_path):
        LOG.error("brain not found at %s", cfg.brain_path)
        return 0
    with open(cfg.brain_path, "r", encoding="utf-8") as fh:
        text = fh.read()

    seen = existing_hashes(text)
    today = dt.date.today()
    new_blocks = []
    added = 0
    for entry in entries:
        h = entry.source_hash()
        if h in seen:
            continue
        score = combined_score(entry, today)
        if score < cfg.min_relevance:
            LOG.debug("skip low-relevance: %s (%.3f)", entry.title, score)
            continue
        seen.add(h)
        new_blocks.append(render_entry(entry, today, score))
        added += 1

    if added and not cfg.dry_run:
        block = f"\n<!-- crawl {today.isoformat()}: +{added} entries -->\n" + "".join(new_blocks)
        with open(cfg.brain_path, "a", encoding="utf-8") as fh:
            fh.write(block)
        LOG.info("appended %d new entries to %s", added, cfg.brain_path)
    elif added and cfg.dry_run:
        LOG.info("dry-run: would append %d entries", added)
    else:
        LOG.info("no new entries to append (all deduped/filtered)")
    return added


def load_config(path: str) -> RunConfig:
    cfg = RunConfig()
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for f in dataclasses.fields(RunConfig):
            if f.name in data:
                setattr(cfg, f.name, data[f.name])
    return cfg


def save_config(cfg: RunConfig, path: str) -> None:
    payload = dataclasses.asdict(cfg)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="knowledge_updater",
        description="Refresh SECOND-KNOWLEDGE-BRAIN.md for the software-supply-chain-security skill.",
    )
    p.add_argument("--brain", default=DEFAULT_BRAIN, help="path to the knowledge brain markdown")
    p.add_argument("--config", default=DEFAULT_CONFIG, help="path to a JSON config file")
    p.add_argument("--min-relevance", type=float, default=MIN_RELEVANCE, help="drop entries below this score")
    p.add_argument("--no-crawl4ai", action="store_true", help="disable crawl4ai, use urllib only")
    p.add_argument("--no-fallback", action="store_true", help="disable urllib fallback")
    p.add_argument("--max-entries", type=int, default=25, help="max entries per source")
    p.add_argument("--dry-run", action="store_true", help="score+dedupe but do not write")
    p.add_argument("--save-config", action="store_true", help="write current options to --config and exit")
    p.add_argument("--log-level", default="INFO", help="DEBUG/INFO/WARNING/ERROR")
    return p


def run(cfg: RunConfig) -> int:
    LOG.info("starting knowledge crawl for software-supply-chain-security ...")
    entries = asyncio.run(collect_entries(cfg))
    LOG.info("collected %d raw entries", len(entries))
    n = append_entries(entries, cfg)
    LOG.info("done; %d entries added.", n)
    return 0


def main(argv: Optional[list] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    setup_logging(args.log_level)
    cfg = load_config(args.config)
    cfg.brain_path = args.brain
    cfg.min_relevance = args.min_relevance
    cfg.use_crawl4ai = not args.no_crawl4ai
    cfg.use_urllib_fallback = not args.no_fallback
    cfg.max_entries_per_source = args.max_entries
    cfg.dry_run = args.dry_run
    cfg.log_level = args.log_level
    if args.save_config:
        save_config(cfg, args.config)
        LOG.info("config written to %s", args.config)
        return 0
    try:
        return run(cfg)
    except Exception as exc:
        LOG.error("knowledge update aborted: %s", exc)
        return 0


if __name__ == "__main__":
    sys.exit(main())
