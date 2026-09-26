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

> **Status: early development (phase F1).** Right now only Syft + OSV-Scanner are wired in. See
> [`docs/bitacora.md`](docs/bitacora.md) for progress.

## How it works

```
input (directory / lockfile / ecosystem:package@version)
  → Syft (SBOM)
  → collectors: osv, guarddog, scorecard, depsdev   (one module each, same interface)
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
.venv/Scripts/python -m pip install -e ".[dev]"     # Windows; use .venv/bin on Linux/macOS

eslabon scan path/to/project              # directory: Syft builds the SBOM
eslabon scan path/to/package-lock.json    # a single lockfile
eslabon scan pypi:requests@2.19.0         # a single package, no files needed
eslabon scan . --formato json -o out.json
```

**eslabon never installs or executes the packages it analyzes.** All analysis is static or
metadata-based.

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
