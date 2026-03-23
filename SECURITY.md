# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (main branch) | ✅ |
| Older releases       | ⚠️ Best-effort only |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**
Public disclosure before a fix is available puts all users at risk.

### Preferred Channel
Use **GitHub Private Vulnerability Reporting**:
`Security` → `Report a vulnerability` on this repository page.

### Alternatively
Email the maintainers directly (see CONTRIBUTORS section of README).
Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

### Response Timeline
| Action | Target Time |
|--------|------------|
| Acknowledgement | 48 hours |
| Initial assessment | 5 business days |
| Fix release | 30–90 days depending on severity |
| Public disclosure | 90 days after report (coordinated) |

We follow responsible disclosure. Credit will be given to reporters in
the release notes unless you prefer to remain anonymous.

## Security Scope

This tool is itself a security tool — we take its own security seriously.
In-scope for reports:
- SSRF/injection vulnerabilities in the scanner itself
- Unsafe subprocess execution
- Secret leakage from the tool (not from scanned targets)
- Authentication / authorization bypass in the API layer
- SQLite injection in the tool's own database queries

Out-of-scope:
- Vulnerabilities found *by* the tool in external targets (that's intended behavior)
- Reports requiring physical access to the machine running the tool
