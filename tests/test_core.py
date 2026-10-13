import json
import subprocess
from types import SimpleNamespace

import pytest

from securesupply.cli import main
from securesupply.dependencies import collect_pins
from securesupply.models import Check, Finding, Gate
from securesupply.paths import snapshot, validate_repository
from securesupply.report import write_reports
from securesupply.scanners import execute, parse_output, sanitized_env


def test_valid_directory(tmp_path):
    assert validate_repository(str(tmp_path)) == tmp_path


def test_environment_keeps_network_settings_not_api_keys(monkeypatch):
    monkeypatch.setenv("https_proxy", "http://proxy.example:8080")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/certificates/trusted.pem")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-value")
    result = sanitized_env()
    assert result["https_proxy"] == "http://proxy.example:8080"
    assert result["REQUESTS_CA_BUNDLE"] == "/certificates/trusted.pem"
    assert "AWS_SECRET_ACCESS_KEY" not in result


@pytest.mark.parametrize("value", ["missing", "/"])
def test_invalid_path(value):
    with pytest.raises((ValueError, OSError)):
        validate_repository(value)


def test_file_is_not_repository(tmp_path):
    f = tmp_path / "file"
    f.touch()
    with pytest.raises(ValueError):
        validate_repository(str(f))


def test_snapshot_symlinks_and_limits(tmp_path):
    root, out = tmp_path / "repo", tmp_path / "copy"
    root.mkdir()
    outside = tmp_path / "private"
    outside.write_text("secret")
    try:
        (root / "link").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink test needs filesystem symlink support (Windows may require Developer Mode)")
    (root / ".bandit").write_text("untrusted configuration")
    (root / "ok.py").write_text("x = 1")
    stats = snapshot(root, out)
    assert stats["files"] == 1 and not (out / "link").exists()
    with pytest.raises(ValueError):
        snapshot(root, out, max_bytes=1)


@pytest.mark.parametrize(
    "line", ["foo>=1", "-r other.txt", "foo @ https://example.org/x", "./pkg", "-e .", "foo==1.*"]
)
def test_reject_executable_manifest_forms(tmp_path, line):
    (tmp_path / "requirements.txt").write_text(line)
    with pytest.raises(ValueError):
        collect_pins(tmp_path)


def test_requirements_pins_and_markers(tmp_path):
    (tmp_path / "requirements.txt").write_text("Foo_Bar==1.2; python_version > '3.9'\n# comment\n")
    assert collect_pins(tmp_path) == ["foo-bar==1.2"]


@pytest.mark.parametrize("lock", ["uv.lock", "poetry.lock"])
def test_locks(tmp_path, lock):
    (tmp_path / lock).write_text('[[package]]\nname="foo"\nversion="1.2"\n')
    assert collect_pins(tmp_path) == ["foo==1.2"]


def test_manifest_traversal(tmp_path):
    with pytest.raises(ValueError):
        collect_pins(tmp_path, "../requirements.txt")


@pytest.mark.parametrize("severity,code", [("LOW", 0), ("HIGH", 1), ("CRITICAL", 1), ("UNKNOWN", 1)])
def test_gate_thresholds(severity, code):
    check = Check("bandit", "failed", findings=[Finding("bandit", "rule", severity, "finding")])
    assert Gate(required=("bandit",)).evaluate([check])[0] == code


@pytest.mark.parametrize("status", ["skipped", "unavailable", "error"])
def test_incomplete_gate(status):
    assert Gate(required=("bandit",)).evaluate([Check("bandit", status)])[0] == 2


def test_empty_gate_and_reports(tmp_path):
    assert Gate(required=()).evaluate([])[0] == 0
    assert Gate().evaluate([])[0] == 2
    report = {
        "created_at": "test",
        "checks": [],
        "exit_code": 2,
        "gate_message": "<script>alert(1)</script>",
        "scope": {},
    }
    write_reports(report, tmp_path)
    page = (tmp_path / "report.html").read_text()
    assert "<script>" not in page and "&lt;script&gt;" in page
    assert json.loads((tmp_path / "report.json").read_text())["exit_code"] == 2


def test_secrets_are_not_in_normalized_report(tmp_path):
    rows = parse_output(
        "gitleaks",
        [{"RuleID": "test", "File": "x", "StartLine": 2, "Secret": "DO-NOT-KEEP", "Match": "DO-NOT-KEEP"}],
        tmp_path,
    )
    assert "DO-NOT-KEEP" not in str(rows)


def test_dependency_and_trivy_parse(tmp_path):
    dep = {
        "dependencies": [
            {"name": "foo", "version": "1", "vulns": [{"id": "CVE-test", "fix_versions": ["2"]}]}
        ]
    }
    assert parse_output("dependencies", dep, tmp_path)[0].severity == "UNKNOWN"
    payload = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [{"ID": "AVD-test", "Severity": "HIGH", "Title": "Root user"}],
            }
        ],
    }
    assert parse_output("trivy", payload, tmp_path)[0].rule == "AVD-test"


def test_missing_tool(monkeypatch, tmp_path):
    monkeypatch.setattr("securesupply.scanners.shutil.which", lambda name: None)
    assert execute("bandit", "bandit", [], tmp_path / "out", tmp_path, tmp_path, 1).status == "unavailable"


@pytest.mark.parametrize("content", ["garbage", "{}", '{"results":null}', '{"results":[],"errors":[{}]}'])
def test_malformed_scanner_output(monkeypatch, tmp_path, content):
    out = tmp_path / "out.json"
    out.write_text(content)
    monkeypatch.setattr("securesupply.scanners.shutil.which", lambda name: "/trusted/bandit")
    monkeypatch.setattr(
        "securesupply.scanners.subprocess.run", lambda *a, **kw: SimpleNamespace(returncode=0)
    )
    assert execute("bandit", "bandit", [], out, tmp_path, tmp_path, 1).status == "error"


def test_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr("securesupply.scanners.shutil.which", lambda name: "/trusted/bandit")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("bandit", 1)

    monkeypatch.setattr("securesupply.scanners.subprocess.run", timeout)
    assert execute("bandit", "bandit", [], tmp_path / "o", tmp_path, tmp_path, 1).status == "error"


def test_cli_actual_missing_tools(monkeypatch, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("packaging==26.3")
    monkeypatch.setattr("securesupply.scanners.shutil.which", lambda name: None)
    assert main([str(root), "--output", str(tmp_path / "reports")]) == 2
    data = json.loads((tmp_path / "reports/report.json").read_text())
    assert all(c["status"] == "unavailable" for c in data["checks"])
