---
name: software-supply-chain-security__sub-inventory-intake
description: Sub-skill of software-supply-chain-security — Capture dependency manifests, build pipeline config, registries and provenance metadata into a normalized, evidence-linked SBOM-shaped record.
---

## Purpose
Capture, normalize and validate everything needed to reason about a software supply chain: dependency manifests, lockfiles, SBOMs, build pipeline configuration, package registries in use, artifact provenance/signing metadata and the organization's policy context. Produce a single structured `InventoryRecord` that every downstream sub-skill consumes. No downstream stage may invent missing inputs; if a required field is absent, intake asks targeted clarifying questions.

## Inputs
The intake accepts any combination of the following; it asks for whatever is missing rather than guessing.

| Field | Type | Required | Source / how to obtain |
|-------|------|----------|------------------------|
| `manifests` | list[ManifestFile] | yes (≥1) | `package.json`, `requirements.txt`/`Pipfile.lock`, `go.mod`, `Cargo.toml`/`Cargo.lock`, `pom.xml`, `build.gradle`, `Gemfile.lock`, `composer.json` |
| `lockfiles` | list[LockFile] | recommended | lockfiles + `*.lock`/`*.checksums` for reproducible resolution |
| `sbom` | SBOMDoc (SPDX/CycloneDX, JSON) | optional but preferred | `syft`, `trivy`, `cyclonedx`/`spdx` CLI, or build-pipeline attestation |
| `pipeline_config` | PipelineConfig | yes | `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`, `buildkite pipeline`, `Tekton` tasks |
| `registries` | list[Registry] | yes | npm, PyPI, Maven Central, Go proxy, private Artifactory/Nexus, GHCR, Docker Hub |
| `provenance` | list[Provenance] | recommended | Sigstore `cosign` attestations, SLSA provenance JSON, build logs w/ hash |
| `policy` | PolicyContext | yes | allowed/disallowed licenses, max CVSS, required SLSA level, maintainer-trust rules |
| `env_context` | EnvContext | yes | language(s), OS targets, deployment model, regulated? (FedRAMP/PCI/HIPAA/SOC2) |
| `scope` | enum | yes | `full` | `single-package` | `pipeline-only` |
| `time_budget` | enum | yes | `express` (<2 min) | `standard` | `deep` |

### When inputs are missing
Ask targeted, ranked questions (max 5 per round), grouped by priority:
1. **Blockers** — no manifests/pipeline/policy: analysis cannot start.
2. **Quality** — no SBOM/provenance/lockfile: analysis can run in `degraded` mode, but signal the limitation.
3. **Nice-to-have** — `env_context` refinements.

Do **not** proceed to scoring with a blocker missing. Re-state exactly which blocker is outstanding.

## Procedure
1. **Parse & normalize** each manifest/lockfile/SBOM into a common `DependencyNode` shape (see Output Schema). Collapse duplicates across manifests by `(ecosystem, name, version)`.
2. **Resolve versions** from lockfiles where present; if only a manifest is given with version ranges, record `resolved_version = null` and flag `version_pinned = false`.
3. **Enrich each node** with registry origin, license expression (SPDX), maintainer identity (name, email, publish key fingerprint), download count / popularity proxy, last-publish date, and any attached signatures/attestations.
4. **Classify provenance maturity** per artifact using the SLSA level table in `sub-supplychain-scoring`; record the raw signals, not the level (scoring assigns the level).
5. **Capture pipeline surface** — list every external command, secret reference, base image, third-party action/plugin and whether it is pinned to a SHA vs a mutable tag.
6. **Attach policy** — copy the active policy context verbatim into the record so downstream gates can reference it without re-prompting.
7. **Emit** the `InventoryRecord` plus an `IntakeReport` (counts, coverage %, missing-field list, degradation flags).

## Output Schema (structured — consumed downstream, no prose-only answers)
```yaml
InventoryRecord:
  generated_at: <ISO-8601>
  scope: full | single-package | pipeline-only
  degradation_flags: [no_sbom, no_provenance, no_lockfile, offline, ...]
  env_context: { languages, os_targets, deploy_model, regulatory }
  policy:  # verbatim copy of active policy
    allowed_licenses: [...]
    disallowed_licenses: [...]
    max_cvss_to_allow: <float>
    required_slsa_level: <1-4>
    require_signature: bool
    maintainer_trust: { min_downloads, min_age_days, require_2fa }
  dependencies:
    - id: <stable hash of ecosystem|name|version>
      ecosystem: npm | pypi | maven | go | cargo | gem | composer | container | generic
      name: str
      version: str | null
      version_pinned: bool
      is_direct: bool
      registry: str
      license: SPDX-expression | UNKNOWN | NONE
      maintainer: { name, email, key_fingerprint, account_age_days, publish_count, has_2fa }
      popularity: { downloads_30d, stars, forks }
      last_published: ISO-8601 | null
      signature: { scheme: sigstore|gpg|none, verified: bool, attestation_url }
      provenance_signals:
        source_repo: url | null
        build_service: str | null
        build_hash: str | null
        slsa_signals: [provenance_available, isolated_build, hermetic, two_party_review, ...]
      vulnerabilities_known: []   # filled by sub-vuln-scanner
  pipeline:
    platform: github|gitlab|jenkins|azure|buildkite|tekton
    jobs: [ {name, uses_third_party_actions, pinned_to_sha, uses_secrets, runs_on} ]
    base_images: [ {image, digest, is_pinned, scanner_passed} ]
    secrets_handling: { masked_in_logs, oidc_used, vault_used }
  coverage:
    sbom_present: bool
    lockfile_present: bool
    provenance_present: bool
    percent_dependencies_enriched: float
IntakeReport:
  total_dependencies: int
  direct: int
  transitive: int
  missing_required_fields: [...]
  degradation_flags: [...]
  clarifying_questions_asked: [...]
```

## Evidence & Assumption Rules
- Every externally-sourced field (license, maintainer, downloads, signature) carries either a citation (`registry_api`, `osv.dev`, `github.com/...`) or is explicitly tagged `assumption: <reason>`.
- Never fabricate a version, hash or signature status. Unknown ⇒ `null` + flag.
- Record the **as-of timestamp** for every live datum (registry data drifts).

## Quality Gate (must pass before hand-off)
- [ ] All blocker inputs present (manifests, pipeline, policy, env_context, scope).
- [ ] Every dependency node has a stable `id` and a populated `ecosystem|name|version|registry`.
- [ ] Missing-but-recommended inputs are listed under `degradation_flags`, not silently dropped.
- [ ] Each enrichment field is either cited or marked `assumption`.
- [ ] No clarifying question remains unanswered if it was a blocker.
- [ ] `IntakeReport` emitted alongside the `InventoryRecord`.

## Hand-off
Downstream: `sub-vuln-scanner` (fills `vulnerabilities_known`), `sub-compliance-check` (reads `policy` + `license` fields), `sub-supplychain-scoring` (consumes `provenance_signals` + `pipeline`).
