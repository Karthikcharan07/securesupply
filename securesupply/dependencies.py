import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

PIN = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+!-]+$")


def collect_pins(root: Path, manifest: str | None = None) -> list[str]:
    """Parse inert package records; reject URLs, options, includes and resolution.

    Supports flat pinned requirements and named uv.lock/poetry.lock records.
    Conditional records are conservatively all audited (cross-platform superset).
    """
    candidates = [manifest] if manifest else ["requirements.txt", "uv.lock", "poetry.lock"]
    path = None
    for candidate in candidates:
        p = (root / candidate).resolve()
        if not p.is_relative_to(root.resolve()):
            raise ValueError("Manifest must be inside the repository")
        if p.is_file():
            path = p
            break
    if path is None:
        raise FileNotFoundError("No supported dependency manifest")
    entries = []
    if path.name in {"uv.lock", "poetry.lock"}:
        for pkg in tomllib.loads(path.read_text(encoding="utf-8")).get("package", []):
            source = pkg.get("source", {})
            if "version" not in pkg or any(
                k in source for k in ("git", "path", "url", "editable", "virtual")
            ):
                raise ValueError(
                    "Lock contains local/URL dependencies; export a registry-only pinned manifest"
                )
            if source and "registry" not in source and source.get("type") not in {"legacy", "index"}:
                raise ValueError("Unsupported lock source")
            entries.append(f"{pkg['name']}=={pkg['version']}")
    else:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.split(" #", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            # Environment markers are not evaluated: scan all declared variants.
            entries.append(line.split(";", 1)[0].strip())
    pins = set()
    for entry in entries:
        if not PIN.fullmatch(entry):
            raise ValueError("Use flat exact == pins; URLs, ranges, includes and options are unsupported")
        req = Requirement(entry)
        spec = next(iter(req.specifier))
        Version(spec.version)
        pins.add(f"{canonicalize_name(req.name)}=={spec.version}")
    return sorted(pins)
