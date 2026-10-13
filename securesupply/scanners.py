import json
import os
import shutil
import subprocess  # nosec B404
import tempfile
from pathlib import Path

from .dependencies import collect_pins
from .models import Check, Finding

TRUSTED_CONFIG = Path(__file__).parent / "gitleaks.toml"


def relative_file(value, root):
    p = Path(value)
    if p.is_absolute():
        try:
            return str(p.relative_to(root))
        except ValueError:
            return p.name
    return str(p)


def parse_output(tool: str, payload, root: Path) -> list[Finding]:
    """Deliberately drop source snippets, secret strings and arbitrary raw logs."""
    findings = []
    if tool == "dependencies":
        for dep in payload["dependencies"]:
            if "skip_reason" in dep:
                raise ValueError("Dependency could not be audited")
            for vuln in dep["vulns"]:
                findings.append(
                    Finding(
                        tool,
                        vuln["id"],
                        "UNKNOWN",
                        "Known dependency vulnerability; pip-audit does not supply uniform CVSS severity",
                        package=dep["name"],
                        version=dep["version"],
                        fixes=vuln.get("fix_versions", []),
                    )
                )
    elif tool == "bandit":
        if payload.get("errors"):
            raise ValueError("Bandit reported incomplete file analysis")
        for row in payload["results"]:
            findings.append(
                Finding(
                    tool,
                    row["test_id"],
                    row["issue_severity"].upper(),
                    row["issue_text"],
                    relative_file(row["filename"], root),
                    row["line_number"],
                )
            )
    elif tool == "gitleaks":
        if not isinstance(payload, list):
            raise ValueError("Invalid Gitleaks output")
        for row in payload:
            findings.append(
                Finding(
                    tool,
                    row["RuleID"],
                    "HIGH",
                    "Potential exposed secret (redacted)",
                    relative_file(row["File"], root),
                    row["StartLine"],
                )
            )
    elif tool == "trivy":
        if not isinstance(payload, dict) or "SchemaVersion" not in payload:
            raise ValueError("Invalid Trivy output")
        for result in payload.get("Results", []):
            for row in result.get("Misconfigurations", []):
                findings.append(
                    Finding(
                        tool,
                        row["ID"],
                        row["Severity"].upper(),
                        row["Title"],
                        relative_file(result["Target"], root),
                        row.get("CauseMetadata", {}).get("StartLine", 0),
                    )
                )
    return findings


def sanitized_env():
    # Avoid passing cloud/API credentials and interpreter injection to scanners.
    allowed = {
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "all_proxy",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    }
    return {k: v for k, v in os.environ.items() if k in allowed}


def execute(tool, executable, args, output, root, work, timeout):
    binary = shutil.which(executable)
    if not binary:
        return Check(tool, "unavailable", f"Install {executable} and add it to PATH")
    # Executables are resolved from the operator's PATH, never scanned repo cwd.
    try:
        completed = subprocess.run(  # nosec B603
            [binary, *args],
            cwd=work,
            env=sanitized_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        if completed.returncode not in {0, 1} or not output.is_file():
            return Check(
                tool, "error", f"Scanner did not produce a valid report (exit {completed.returncode})"
            )
        payload = json.loads(output.read_text(encoding="utf-8"))
        if tool == "sbom":
            if completed.returncode or payload.get("bomFormat") != "CycloneDX":
                raise ValueError("Invalid SBOM")
            return Check(tool, "passed", "CycloneDX SBOM generated from declared package pins")
        findings = parse_output(tool, payload, root)
        if completed.returncode == 1 and not findings:
            return Check(tool, "error", "Nonzero exit without normalized findings")
        return Check(tool, "failed" if findings else "passed", f"{len(findings)} findings", findings)
    except subprocess.TimeoutExpired:
        return Check(tool, "error", "Scanner timeout; results are incomplete")
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return Check(tool, "error", "Malformed, unsupported, or incomplete scanner output")


def run_scanners(
    root: Path, output: Path, timeout: int, selected: set[str], manifest=None, vulnerability_service="osv"
):
    checks = []
    (output / "sbom.cdx.json").unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="securesupply-tools-") as tmp:
        work = Path(tmp)
        pin_file = work / "requirements.txt"
        pin_error = None
        try:
            pins = collect_pins(root, manifest)
            pin_file.write_text("\n".join(pins) + "\n", encoding="utf-8")
            if not pins:
                pin_error = ("skipped", "Manifest has no dependency records")
        except FileNotFoundError:
            pin_error = ("skipped", "No supported dependency manifest")
        except (ValueError, KeyError, TypeError, OSError):
            pin_error = ("error", "Manifest is unsupported or unsafe; use flat exact registry pins")
        for tool in ("dependencies", "bandit", "gitleaks", "sbom", "trivy"):
            if tool not in selected:
                checks.append(Check(tool, "skipped", "Not selected"))
                continue
            if tool in {"dependencies", "sbom"} and pin_error:
                checks.append(Check(tool, *pin_error))
                continue
            raw = work / f"{tool}.json"
            if tool == "dependencies":
                executable = "pip-audit"
                args = [
                    "-r",
                    str(pin_file),
                    "--no-deps",
                    "--disable-pip",
                    "--strict",
                    "--vulnerability-service",
                    vulnerability_service,
                    "--timeout",
                    "20",
                    "-f",
                    "json",
                    "-o",
                    str(raw),
                ]
            elif tool == "bandit":
                executable = "bandit"
                args = ["-r", str(root), "-f", "json", "-o", str(raw)]
            elif tool == "gitleaks":
                executable = "gitleaks"
                args = [
                    "dir",
                    str(root),
                    "--config",
                    str(TRUSTED_CONFIG),
                    "--redact=100",
                    "--no-banner",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(raw),
                ]
            elif tool == "sbom":
                executable = "cyclonedx-py"
                args = ["requirements", str(pin_file), "--output-format", "JSON", "-o", str(raw)]
            else:
                executable = "trivy"
                ignore = work / "empty-ignore"
                ignore.touch()
                args = [
                    "fs",
                    "--scanners",
                    "misconfig",
                    "--ignorefile",
                    str(ignore),
                    "--format",
                    "json",
                    "--output",
                    str(raw),
                    str(root),
                ]
            check = execute(tool, executable, args, raw, root, work, timeout)
            checks.append(check)
            if tool == "sbom" and check.status == "passed":
                shutil.copyfile(raw, output / "sbom.cdx.json")
    return checks
