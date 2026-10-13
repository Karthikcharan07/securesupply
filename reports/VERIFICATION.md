# Actual local verification

Verified on 2026-10-13 with Python 3.12.14 on Linux in a fresh, isolated virtual environment.
Both declared requirements sets plus dev packages were installed; editable project installation worked.
`python -m pip check`: **No broken requirements found**.
This record describes performed local checks; the remote GitHub workflow was not run.

| Check | Actual outcome |
|---|---|
| pytest | 33 passed |
| Ruff lint | Passed |
| Ruff format check | Passed |
| Bandit application and scripts | 0 findings, 0 analysis errors |
| pip-audit declared runtime packages (PyPI) | 4 packages audited, no known vulnerabilities |
| pip-audit installed third-party environment | 79 package versions audited, no known vulnerabilities |
| Gitleaks current project files | No leaks found |
| Trivy filesystem misconfigurations | 2 findings, no HIGH/CRITICAL findings |
| GitHub Actions YAML | Parsed; job structure and project paths checked |
| Docker build/runtime | Not run: Docker is not installed |
| Python 3.11 runtime tests | Not run locally; configured in the GitHub CI matrix |
| GitHub repository upload/workflow execution | Not performed; upload instructions supplied |

Third-party environment auditing used a flat installed-version manifest excluding the two local,
unpublished editable project distributions. An initial strict audit of those distributions correctly
failed because they are not published on PyPI; it was not treated as a security pass. The final
79-package audit includes resolved third-party runtime/dev/build dependencies from the combined
verification environment. It is not a lockfile for another operating system.

Tool versions:
```json
{
  "numpy": "2.3.5",
  "pandas": "2.2.3",
  "scikit-learn": "1.8.0",
  "joblib": "1.5.3",
  "fastapi": "0.143.0",
  "starlette": "1.8.0",
  "pydantic": "2.13.5",
  "uvicorn": "0.54.0",
  "pytest": "9.1.1",
  "httpx": "0.28.1",
  "ruff": "0.17.0",
  "bandit": "1.9.4",
  "pip-audit": "2.10.1",
  "cyclonedx-bom": "7.5.0",
  "packaging": "26.3",
  "pip": "26.2.1",
  "setuptools": "84.0.0"
}
```
External binaries: Gitleaks 8.30.1 and Trivy 0.75.0, downloaded from pinned official releases,
checked against release checksum manifests, then actually executed. Advisory results are a dated
snapshot, not a promise that these versions will remain vulnerability-free.

## Configuration findings

| Severity | Rule | Finding | File |
|---|---|---|---|
| LOW | DS-0026 | No HEALTHCHECK defined | Dockerfile |
| LOW | DS-0026 | No HEALTHCHECK defined | examples/safe-repo/Dockerfile |

The CLI image and inert sample container are short-lived commands; the missing-healthcheck LOW findings remain explicit. No HIGH/CRITICAL issue was hidden.

## Final real safe-sample audit

Command (with tools installed in PATH):
```bash
python -m securesupply examples/safe-repo --output reports/verified-final-sample --timeout 90
```
All five checks completed. OSV dependency audit: 0 findings; Bandit: 0 findings;
Gitleaks: 0 findings; CycloneDX SBOM generated; Trivy: 1 LOW missing-healthcheck finding.
Trivy check status is `failed` because it found an issue; the configured HIGH security gate returned
exit 0 because the finding is below that threshold. This is not a claim of zero findings.

An earlier audit could not reach OSV while the scanner's network-environment allowlist omitted
standard lowercase proxy and CA-bundle settings. The allowlist was corrected, a regression test
was added, and the final real audit succeeded with OSV. No mocked result replaced that audit.

Retained evidence: `verified-final-sample/report.json`, `report.html`, and `sbom.cdx.json`;
`dependency-audit.json`, `source-bandit.json`, `gitleaks.json`, `trivy.json`, `pytest.txt` and `ruff.txt`.
