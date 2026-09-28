# eslabon

> *"El eslabón débil de tu cadena"*: find the weak link in your software supply chain.

**eslabon** is a CLI that **orchestrates existing open source supply chain scanners**, normalizes and
correlates what they find, and emits the results as **SIEM-ready alerts** mapped to MITRE ATT&CK
(`T1195.001` *Compromise Software Dependencies and Development Tools*, `T1195.002`).

It does not try to replace Trivy or Grype. What it adds:

1. **Weak-signal correlation.** A freshly published version, an install script that reaches the
   network, and a brand-new maintainer are each noise on their own. Together they are the typical
   pattern of a compromised package.
2. **Explainability.** Every finding states why it was raised, with evidence from each source.
3. **SOC-native output.** JSON events for a Wazuh agent, plus a Wazuh decoder/rules and Sigma rules.

> **Status: early development (phases F0–F4 done).** All sources run for real, GuardDog included
> (via Docker, image pinned by digest). The Wazuh rules are **not yet validated against a real
> manager**. See [`docs/bitacora.md`](docs/bitacora.md) and [`docs/scoring.md`](docs/scoring.md).
>
> Real-world example: `eslabon scan npm:event-stream@3.3.5`. That is the first release published
> by the attacker in the 2018 event-stream incident, and it has **no advisory at all**. eslabon flags
> it as *suspicious* by correlating a new publisher on npm, a release after 779 days of inactivity
> and an archived upstream repo.

## How it works

```
input (directory / lockfile / ecosystem:package@version)
  → Syft (SBOM)
  → collectors: osv, depsdev, npm registry, scorecard, guarddog   (same interface)
  → normalizer  → common Finding schema
  → correlator  → alias dedup (GHSA/CVE/MAL/PYSEC) + explainable score
  → outputs     → console table | JSON | SARIF 2.1.0 | SIEM JSON events
```

External tools run as **separate processes** and their JSON output is parsed. No code is copied or
vendored. If a tool is missing or fails, it is listed under `fuentes_omitidas` (skipped sources)
and the scan carries on.

## Requirements

- Python 3.11+
- [Syft](https://github.com/anchore/syft) and [OSV-Scanner](https://github.com/google/osv-scanner)
  on `PATH`, or pointed to with `ESLABON_SYFT` / `ESLABON_OSV_SCANNER`
- Optional (later phases): GuardDog (via Docker on Windows), OpenSSF Scorecard + `GITHUB_TOKEN`

Installation steps, with checksum verification, are in [`docs/instalacion.md`](docs/instalacion.md).

## Usage

```bash
python -m venv .venv
# Hash-pinned install (pip refuses any file whose SHA256 doesn't match the lockfile):
.venv/Scripts/python -m pip install --require-hashes --no-deps -r requirements-dev.txt
.venv/Scripts/python -m pip install --no-deps -e .   # Windows; use .venv/bin on Linux/macOS

eslabon scan path/to/project              # directory: Syft builds the SBOM
eslabon scan path/to/package-lock.json    # a single lockfile
eslabon scan pypi:requests@2.19.0         # a single package, no files needed
eslabon scan . --formato json -o out.json
```

**eslabon never installs or executes the packages it analyzes.** All analysis is static or
metadata-based.

Output formats: `-f tabla` (default), `json`, `sarif` (SARIF 2.1.0, for GitHub Code Scanning) and
`siem` (JSON Lines for Wazuh; see [`integrations/wazuh`](integrations/wazuh/README.md) and
[`integrations/sigma`](integrations/sigma/README.md)).

SARIF file paths are relative to the repository root (`%SRCROOT%`), which is where GitHub looks
for them. By default that root is the current directory. If you run eslabon from somewhere
else, pass the root explicitly:

```bash
eslabon scan repo/services/api -f sarif -o eslabon.sarif --srcroot repo
# → locations like "services/api/package-lock.json"
```

Exit codes (safe for CI; it fails closed):

| Code | Meaning |
|---|---|
| 0 | No findings at or above `--fallar-en` (default `alta`) |
| 1 | Findings at or above `--fallar-en` |
| 2 | Usage error |
| 3 | Incomplete analysis (no inventory, or the advisory source failed). Zero findings here is **not** a clean result. Use `--permitir-degradado` to opt out |

Security notes:
- External tools are resolved from `PATH` only, never from the current directory.
- `.bat` and `.cmd` wrappers are refused.
- Tools run without secrets in their environment. Only Scorecard gets `GITHUB_TOKEN`.
- Package names from lockfiles are validated against each registry's grammar.
- Error text is redacted before it reaches any output.
- In CI, do not let untrusted contributors set `ESLABON_*` variables: they choose which command
  runs.

## Development

```bash
pytest                     # unit tests use recorded tool output, no network
pytest -m integracion      # runs the real Syft / OSV-Scanner if installed
ruff check .
```

## License

Apache-2.0. See [LICENSE](LICENSE).

---

## Resumen en español

**eslabon** es un CLI en Python que orquesta herramientas open source de seguridad de la cadena de
suministro de software:
- **Syft** genera el inventario de dependencias (SBOM).
- **OSV-Scanner** busca vulnerabilidades y paquetes maliciosos ya conocidos.
- **GuardDog** aplica heurísticas sobre el código de cada paquete.
- **OpenSSF Scorecard** mide la salud del repositorio de origen.
- **deps.dev** aporta metadatos.

eslabon normaliza y correlaciona esos resultados, explica por qué levanta cada hallazgo y los emite
también como eventos JSON para un SIEM (Wazuh), con reglas Sigma y mapeo a MITRE ATT&CK T1195.
**Nunca instala ni ejecuta los paquetes que analiza.** La documentación del proyecto está en
[`docs/`](docs/), en español.
