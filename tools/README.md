# tools/knowledge_updater.py

Self-improving knowledge pipeline for the `software-supply-chain-security` skill
(idea #207). It grows `SECOND-KNOWLEDGE-BRAIN.md` with scored, de-duplicated,
date-stamped entries harvested from ArXiv (cs.CR, cs.SE) and authoritative
domain sources (slsa.dev, owasp.org, osv.dev, sigstore.dev, cisa.gov).

## Requirements
- Python 3.10+
- **No required third-party packages.** The stdlib `urllib` path runs out of
  the box (degraded mode: ArXiv Atom API + static HTML fetch).
- Optional, for JS-rendered pages: `pip install -r tools/requirements.txt`

## Usage
```bash
# Refresh the brain (uses crawl4ai if installed, else urllib fallback)
python tools/knowledge_updater.py

# Score + de-duplicate only, do not write anything
python tools/knowledge_updater.py --dry-run

# Stdlib-only (no crawl4ai), higher max results
python tools/knowledge_updater.py --no-crawl4ai --max-entries 50

# Persist current CLI options to a config file for cron use
python tools/knowledge_updater.py --no-crawl4ai --save-config
```

### Options
| Flag | Default | Purpose |
|------|---------|---------|
| `--brain` | `../SECOND-KNOWLEDGE-BRAIN.md` | target knowledge brain |
| `--config` | `knowledge_updater.config.json` | JSON config (read & `--save-config` writes) |
| `--min-relevance` | `0.05` | drop entries below this combined score |
| `--no-crawl4ai` | off | disable crawl4ai, stdlib only |
| `--no-fallback` | off | disable urllib fallback (crawl4ai only) |
| `--max-entries` | `25` | max entries per source |
| `--dry-run` | off | score + dedupe, no write |
| `--save-config` | off | write options to `--config` and exit |
| `--log-level` | `INFO` | DEBUG / INFO / WARNING / ERROR |

## Scoring
`combined = relevance * 0.6 + recency * 0.4`, where:
- `relevance` = keyword-hit ratio against the title+abstract blob (0..1),
- `recency`   = linear decay 1.0 → 0.1 over 365 days.

Entries below `--min-relevance` are dropped; entries whose `sha256(url)` hash is
already in the brain are skipped (idempotent re-runs).

## Weekly cron (Linux/macOS)
```cron
# Refresh the supply-chain knowledge brain every Monday 03:00
0 3 * * 1  cd /path/to/software-supply-chain-security && python tools/knowledge_updater.py >> logs/knowledge_updater.log 2>&1
```

## Weekly scheduled task (Windows)
```powershell
$action  = New-ScheduledTaskAction -Execute "python" -Argument "tools\knowledge_updater.py" -WorkingDirectory "D:\skills\software-supply-chain-security"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 3am
Register-ScheduledTask -TaskName "SupplyChainKnowledgeUpdater" -Action $action -Trigger $trigger
```

## Robustness guarantees
- On any fetch/parse/network error the tool **logs and exits 0** so the skill
  keeps operating from the existing brain between refreshes.
- Re-running the same week never duplicates entries (hash-based dedupe).
- Configurable via CLI flags and/or a JSON config file.
