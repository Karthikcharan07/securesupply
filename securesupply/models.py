from dataclasses import asdict, dataclass, field

SEVERITIES = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str
    message: str
    file: str = ""
    line: int = 0
    package: str = ""
    version: str = ""
    fixes: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.severity = self.severity.upper()
        if self.severity not in SEVERITIES:
            self.severity = "UNKNOWN"


@dataclass
class Check:
    tool: str
    status: str  # passed / failed (findings) / skipped / unavailable / error
    detail: str = ""
    findings: list[Finding] = field(default_factory=list)

    def dict(self):
        return asdict(self)


@dataclass
class Gate:
    fail_on: str = "HIGH"
    fail_unknown: bool = True
    required: tuple[str, ...] = ("dependencies", "bandit", "gitleaks", "sbom", "trivy")

    def evaluate(self, checks: list[Check]) -> tuple[int, str]:
        if self.fail_on not in SEVERITIES:
            raise ValueError("Invalid severity threshold")
        for check in checks:
            for f in check.findings:
                if (f.severity == "UNKNOWN" and self.fail_unknown) or (
                    SEVERITIES.get(f.severity, -1) >= SEVERITIES[self.fail_on]
                ):
                    return 1, "Security findings exceed the configured gate"
        by_name = {c.tool: c for c in checks}
        if any(t not in by_name or by_name[t].status not in {"passed", "failed"} for t in self.required):
            return 2, "Required checks did not complete"
        return 0, "Configured gate passed; inspect check coverage"
