# Supply Chain Risk Report — `eslabon`

**Scanned:** `.`  
**Commit:** `75fd23d6ce32`  
**Manifests read:** `pyproject.toml`, `requirements-dev.txt`, `requirements.txt`  
**Scanned at:** 2026-09-27T01:15:19+00:00  
**Direct dependencies:** 37 (PyPI 37)

## Summary

- **1 of 37 dependencies have known advisories.** See the findings below.
- Transitive dependencies were **not examined**: no lockfile resolves the transitive tree (package-lock.json, uv.lock, or a go 1.17+ go.mod).
- 3 of 37 dependencies carry at least one finding, 0 of which reach production.
- Weakest coverage: **Install-time script execution**, established for 0 of 37; the Coverage section lists every criterion.

## Production dependencies

13 dependencies are declared as runtime dependencies and ship in the built artifact. Advisory status is given for every one, clean or not.

| Dependency | Version | Advisories | Other findings |
|---|---|---|---|
| `annotated-doc` | 0.0.5 | none known | — |
| `annotated-types` | 0.8.0 | none known | — |
| `colorama` | 0.4.6 | none known | — |
| `markdown-it-py` | 4.2.0 | none known | — |
| `mdurl` | 0.1.2 | none known | — |
| `pydantic` | 2.13.5 (latest, not the project's pin) | none known | — |
| `pydantic-core` | 2.46.5 | none known | — |
| `pygments` | 2.21.0 | none known | — |
| `rich` | 15.0.0 (latest, not the project's pin) | none known | — |
| `shellingham` | 1.5.4 | none known | — |
| `typer` | 0.27.2 (latest, not the project's pin) | none known | — |
| `typing-extensions` | 4.16.0 | none known | — |
| `typing-inspection` | 0.4.4 | none known | — |

## Findings

### Build-time only

Declared as development dependencies. A compromise here reaches build and CI hosts rather than users of the shipped artifact.

| Dependency | Version | Weekly downloads | Findings |
|---|---|---|---|
| `diskcache` | 5.6.3 | — | 2 advisories affect the pinned 5.6.3; no push in 2 years (last 2024-08-10) |
| `diskcache-stubs` | 5.6.3.6.20240818 | — | repository is archived |

## Upstream repository and CI hygiene — OpenSSF Scorecard

These criteria describe each dependency's own repository, not the audited
project. Remediation, where any exists, is upstream.

### Build-time only

Declared as development dependencies. A compromise here reaches build and CI hosts rather than users of the shipped artifact.

| Dependency | Version | Weekly downloads | Findings |
|---|---|---|---|
| `packaging` | 26.3 | — | Binary-Artifacts scores 4/10 (below 10) |

## Transitive advisories

Not examined: no lockfile resolves the transitive tree (package-lock.json, uv.lock, or a go 1.17+ go.mod). Commit a lockfile to close this gap.

## Informational

Measured, not flagged.

- **CI token permissions**: median 0/10 across 30 scored dependencies; 16 score below 6. Not flagged — this measures whether CI workflows declare least-privilege tokens, which tracks project maturity rather than the likelihood of malicious code being published.
- **Changes reviewed by a second person**: median 5/10 across 29 scored dependencies; 17 score below 6. Not flagged — this measures the share of recent commits reviewed by a second person, which is low for most small single-maintainer projects and largely restates publisher concentration.
- **Publish provenance**: not determinable for any dependency in this project.
- **Security policy published**: 28 of 37 publish a security policy.
  Without: `annotated-types`, `diskcache`, `diskcache-stubs`, `iniconfig`, `jq`, `mdurl`, `pygments`, `pysigma`, `shellingham`
- **Download volume**: not determinable for any dependency in this project.

## Coverage

What was and was not measured, per criterion.

| Criterion | Tier | Assessed | Flagged | Not assessable |
|---|---|---|---|---|
| Known advisories | A | 37/37 | 1 | 0 |
| Deprecated or yanked | A | 37/37 | 0 | 0 |
| Repository archived | A | 37/37 | 1 | 0 |
| Maintenance activity | A | 37/37 | 1 | 0 |
| Publisher concentration | B | 0/37 | 0 | 37 |
| Install-time script execution | B | 0/37 | 0 | 37 |
| Dangerous CI workflow | scorecard | 30/37 | 0 | 7 |
| CI token permissions | scorecard | 30/37 | 0 | 7 |
| Checked-in binaries | scorecard | 30/37 | 1 | 7 |
| Changes reviewed by a second person | scorecard | 29/37 | 0 | 8 |
| Publish provenance | info | 0/37 | 0 | 37 |
| Security policy published | info | 37/37 | 0 | 0 |
| Download volume | info | 0/37 | 0 | 37 |

## Not assessable

**Checked-in binaries**

- 7 dependencies — OpenSSF Scorecard has no report for this repository: `annotated-doc`, `diskcache-stubs`, `iniconfig`, `rpds-py`, `ruff`, `typer` and 1 more

**Changes reviewed by a second person**

- 7 dependencies — OpenSSF Scorecard has no report for this repository: `annotated-doc`, `diskcache-stubs`, `iniconfig`, `rpds-py`, `ruff`, `typer` and 1 more
- 1 dependency — Scorecard could not evaluate Code-Review (score -1): `referencing`

**Dangerous CI workflow**

- 7 dependencies — OpenSSF Scorecard has no report for this repository: `annotated-doc`, `diskcache-stubs`, `iniconfig`, `rpds-py`, `ruff`, `typer` and 1 more

**Download volume**

- 37 dependencies — PyPI's download counters are disabled and return -1: `annotated-doc`, `annotated-types`, `attrs`, `certifi`, `charset-normalizer`, `colorama` and 31 more

**Install-time script execution**

- 37 dependencies — install-time execution depends on whether a wheel or an sdist is installed, which this collector does not determine: `annotated-doc`, `annotated-types`, `attrs`, `certifi`, `charset-normalizer`, `colorama` and 31 more

**Publish provenance**

- 37 dependencies — PyPI publish attestations are not read by this collector: `annotated-doc`, `annotated-types`, `attrs`, `certifi`, `charset-normalizer`, `colorama` and 31 more

**Publisher concentration**

- 37 dependencies — PyPI publishes no upload ACL, so who can publish this package is not observable: `annotated-doc`, `annotated-types`, `attrs`, `certifi`, `charset-normalizer`, `colorama` and 31 more

**CI token permissions**

- 7 dependencies — OpenSSF Scorecard has no report for this repository: `annotated-doc`, `diskcache-stubs`, `iniconfig`, `rpds-py`, `ruff`, `typer` and 1 more

## Method and caveats

- cache directory ownership was not verified: os.getuid is POSIX-only, so a cache at %TEMP%\supply-chain-risk-auditor-cache owned by another user would not be detected on this platform. Keep the cache under your own user profile, or pass --cache with a private path.
- 7 dependencies are specified as a version range with no lockfile, so their advisories were matched against the current latest release rather than against what this project installs — commit a lockfile for an exact answer: jsonschema, pydantic, pysigma, pytest, rich, ruff, typer
- Repository-level criteria (archived, maintenance activity, security policy, and the Scorecard checks) describe the source repository rather than the package. 37 dependencies resolve to 36 distinct repositories, so one repository can appear as several findings. Shared: github.com/pydantic/pydantic
- Optional tooling detected: npm, osv-scanner. Not installed, so not used: bundler-audit, cargo-audit, pip-audit.
- Direct dependencies only. Advisories attach to the package that ships the affected code, so an umbrella package can look clean while its components are not — rails 5.0.0 reports 0 advisories where actionpack 5.0.0 reports 10. Transitive dependencies were not examined: no lockfile resolves the transitive tree (package-lock.json, uv.lock, or a go 1.17+ go.mod).
- HTTP sources: 128 fetched, 46 served from cache (oldest 0.0h old), 0 refetched as stale, 0 unavailable offline, 0 errors.
