# Security policy

Use this tool only on repositories you are authorized to audit. Report implementation vulnerabilities
privately to the repository owner using GitHub private vulnerability reporting when enabled; do not
post real credentials or sensitive repository content in public issues. No security contact is fabricated.

The project uses trusted executables from operator PATH, fixed arguments, no shell, timeouts,
stdin disabled and a temporary scan snapshot. It rejects unsafe dependency manifest forms and disables
pip resolution. It does not execute repository code, install repository dependencies, build containers
from audited Dockerfiles or load audited scanner configuration. Filesystem links are not copied.

Snapshot exclusions and resource limits are in the report. Quiescent source directories are required;
this is not an OS sandbox or defense against a concurrent attacker modifying the directory mid-copy.
Patch third-party scanners and run under a limited account. Protect report destinations and do not
scan the filesystem root. Subprocess module/command warnings are narrowly annotated in code because
commands are fixed and intentional; suppressions are not exemptions for arbitrary command execution.

Secret output is normalized without source snippets or secret values; raw temporary scanner outputs
are deleted. Reports may still contain private package names or file paths; review before sharing.
HTML escapes scanner-controlled strings and does not load scripts or external resources. Gitleaks scans
current files in the CLI; GitHub CI separately scans history. Detecting a secret requires rotation at
its issuer plus history cleanup as appropriate; deleting a file alone is insufficient.

OSV/PyPI network failures produce incomplete checks, not success. UNKNOWN vulnerability severity
fails by default. Missing tools and unsupported manifests produce explicit coverage states.
The supply-chain security CI gates are genuine and may fail as new advisories are published.
