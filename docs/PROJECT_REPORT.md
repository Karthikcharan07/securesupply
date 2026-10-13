# SecureSupply — academic project report

**Assessment:** DevSecMLOps Internal 1  
**Level:** B.Tech CSE, medium difficulty  
**Project type:** Local rule-based security auditing; no ML dataset

## Abstract
SecureSupply combines established security tools into a reproducible local audit workflow. It
collects validated package/version records, scans a limited static repository copy, normalizes
findings and produces JSON, HTML and CycloneDX outputs. Coverage and policy are represented
separately so missing tools and network failures cannot silently pass a required security gate.

## Problem and objectives
Independent security tools have different output formats and exit behavior. Students and teams
need a single explainable interface to inspect dependencies, Python source, exposed secrets and
infrastructure. Objectives are safe local scanning, genuine external-tool integration, consistent
findings, explicit incomplete states and CI automation.

## Method
1. Validate the selected directory and report destination.
2. Make a bounded copy excluding links, build directories and audited tool configuration.
3. Parse an exact-pinned registry manifest or supported lock records without running package code.
4. Run pip-audit with resolution disabled, Bandit, Gitleaks, CycloneDX and Trivy with timeouts.
5. Parse actual JSON output, omit secret snippets and preserve rule/tool attribution.
6. Evaluate severity and coverage requirements, write reports and return the gate exit code.

The README includes the architecture diagram, stack, installation and exact demonstration commands.

## Data and security
OSV is the default advisory backend; PyPI is selectable. NVD is a documented reference, not a direct
integration. No fabricated vulnerabilities, dataset downloads or CVSS values are used. Dependency
findings without uniform CVSS severity remain UNKNOWN and block by default. SBOM coverage is
limited to the selected declared versions. Secret strings and source snippets are excluded from reports.

## Verification and results
See reports/VERIFICATION.md and retained actual tool reports. The final safe-sample audit completed
all tools and passed the HIGH gate. Trivy reported one LOW missing-healthcheck issue, retained for
transparent review. pytest verifies invalid paths, unsafe manifests, malformed JSON, unavailable tools,
timeouts, thresholds, empty reports and CLI behavior. Docker was not available for a local build.

## Discussion and conclusion
The implemented workflow demonstrates a working DevSecOps gate rather than a guarantee of security.
External advisories can change, rules can miss issues, and declared dependencies may omit transitive
components. Snapshot limits and exclusions must be reviewed. Future extensions include stronger OS
isolation, complete resolved SBOM graphs, reviewed CVSS enrichment and additional analysis engines.
