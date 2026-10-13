# Viva questions and answers

## 1. What is the objective?

Combine tool-backed security checks for dependencies, Python code, secrets and configurations, with reports and configurable CI gates.

## 2. Why is this not an ML project?

It uses established security rules and vulnerability advisories; there is no trained classifier or invented dataset.

## 3. What is a software supply chain?

The packages, source, build tools, artifacts and distribution steps used to produce software.

## 4. What does pip-audit detect?

Known advisories affecting declared package versions. It does not prove a package is safe or detect malicious package behavior.

## 5. Why disable pip resolution?

Normal dependency resolution can run build code. Exact inert package records with --no-deps --disable-pip avoid that execution path.

## 6. What dependencies are covered?

Versions in the selected manifest. To include transitive packages, supply a complete resolved pinned manifest; direct requirements alone cannot reveal all deployed versions.

## 7. What does Bandit do?

It parses Python syntax and checks common insecure patterns without executing the scanned program.

## 8. What does Gitleaks do?

It identifies possible secrets using rules and entropy. The CLI scans current files; CI separately scans git history.

## 9. What should happen after a real secret is found?

Revoke or rotate it at the issuer, investigate use, and clean repository history as appropriate; deletion alone does not revoke it.

## 10. What is an SBOM?

A structured software component inventory. This project uses CycloneDX tooling on declared pinned components; it is not proof of a complete runtime inventory.

## 11. What does Trivy scan here?

Dockerfile and supported infrastructure misconfigurations through filesystem scanning. It does not build or run the image.

## 12. Why normalize findings?

A common schema makes tool attribution, severity thresholds and machine-readable reports consistent.

## 13. Why is dependency severity UNKNOWN?

Pip-audit JSON does not uniformly supply CVSS severity. Inventing HIGH or LOW would misrepresent evidence; UNKNOWN blocks by default.

## 14. How are exit codes interpreted?

0: configured gate passes; 1: finding breaches policy; 2: incomplete required coverage or invalid input. All check statuses still need review.

## 15. What is the difference between failed and error?

Failed means findings were produced by a completed tool. Error means the scan could not reliably complete or its output is invalid.

## 16. Why copy the repository?

A limited static snapshot avoids symlink traversal and audited scanner configuration, isolates temporary outputs and records scope. It is not an OS sandbox.

## 17. How are subprocesses secured?

Fixed trusted executables and argument arrays, no shell, limited environment, disabled stdin and timeouts; no binary or code is selected from the audited repository.

## 18. How does CI improve security?

It reruns tests, SAST, advisory checks, history secrets and configuration checks on changes, and blocks container builds on failing gates.

## 19. Can a clean report guarantee security?

No. Coverage, unknown advisories, scanner limitations, excluded files and false negatives remain.

## 20. What was verified locally?

Actual pytest, lint, Bandit, dependency audits, Gitleaks, CycloneDX and Trivy runs; exact counts and retained evidence are in reports/VERIFICATION.md. Docker was unavailable.

