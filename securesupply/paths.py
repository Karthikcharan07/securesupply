import os
import shutil
from pathlib import Path

EXCLUDED = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "reports",
    "models",
}
CONFIGS = {".bandit", ".gitleaks.toml", ".gitleaksignore", ".trivyignore", "trivy.yaml", "trivy.yml"}


def validate_repository(value: str) -> Path:
    path = Path(value).expanduser().resolve(strict=True)
    if not path.is_dir() or path == Path(path.anchor):
        raise ValueError("Choose a project directory, not a file or filesystem root")
    return path


def snapshot(source: Path, dest: Path, max_bytes=100_000_000, max_files=10_000):
    """No symlinks, no scanner configuration from the audited repository.

    Source must be quiescent; this is resource isolation, not an OS sandbox.
    """
    total = count = skipped = 0
    for root, dirs, files in os.walk(source, followlinks=False):
        dirs[:] = [d for d in dirs if d not in EXCLUDED and not (Path(root) / d).is_symlink()]
        for name in files:
            src = Path(root) / name
            if src.is_symlink() or not src.is_file() or name in CONFIGS:
                skipped += 1
                continue
            size = src.stat().st_size
            total += size
            count += 1
            if total > max_bytes or count > max_files:
                raise ValueError("Repository exceeds snapshot resource limits")
            out = dest / src.relative_to(source)
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, out)
    return {
        "files": count,
        "bytes": total,
        "skipped_links_or_configs": skipped,
        "excluded_directories": sorted(EXCLUDED),
    }
