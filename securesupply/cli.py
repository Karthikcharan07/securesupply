import argparse
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .models import SEVERITIES, Gate
from .paths import snapshot, validate_repository
from .report import write_reports
from .scanners import run_scanners

TOOLS = {"dependencies", "bandit", "gitleaks", "sbom", "trivy"}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Tool-backed static repository audit")
    parser.add_argument("repository")
    parser.add_argument("--output", default="reports/latest")
    parser.add_argument("--manifest", help="Relative pinned requirements or uv.lock/poetry.lock path")
    parser.add_argument("--tools", nargs="+", choices=sorted(TOOLS), default=sorted(TOOLS))
    parser.add_argument("--require", nargs="*", choices=sorted(TOOLS), default=sorted(TOOLS))
    parser.add_argument("--fail-on", choices=SEVERITIES, default="HIGH")
    parser.add_argument("--allow-unknown", action="store_true", help="Allow UNKNOWN severity through gate")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--vulnerability-service", choices=["osv", "pypi"], default="osv")
    args = parser.parse_args(argv)
    try:
        root = validate_repository(args.repository)
        out = Path(args.output).expanduser().resolve()
        if out.is_relative_to(root):
            raise ValueError("Report output must be outside the scanned directory")
        if not 1 <= args.timeout <= 3600:
            raise ValueError("Timeout must be 1..3600 seconds")
        out.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="securesupply-snapshot-") as tmp:
            copied = Path(tmp)
            scope = snapshot(root, copied)
            checks = run_scanners(
                copied, out, args.timeout, set(args.tools), args.manifest, args.vulnerability_service
            )
        code, message = Gate(args.fail_on, not args.allow_unknown, tuple(args.require)).evaluate(checks)
        report = {
            "schema_version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "repository": root.name,
            "vulnerability_service": args.vulnerability_service,
            "scope": scope,
            "checks": [c.dict() for c in checks],
            "gate": {
                "fail_on": args.fail_on,
                "fail_unknown": not args.allow_unknown,
                "required": args.require,
            },
            "exit_code": code,
            "gate_message": message,
        }
        write_reports(report, out)
        print(json.dumps({"exit_code": code, "message": message, "report": str(out / "report.html")}))
        return code
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Input/output error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
