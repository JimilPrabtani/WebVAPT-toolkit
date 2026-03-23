# Contributing to Web Sentinels

Thank you for improving this project. Contributions are welcome from security
engineers, developers, and researchers.

## Getting Started

```bash
git clone https://github.com/your-org/web-sentinels.git
cd web-sentinels
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env   # Add your API key(s)
```

## Types of Contributions

### New Scan Module
1. Create `scanner/your_check.py` implementing `run_all_your_checks(url, response) -> list[Finding]`
2. Import and call it in `scanner/engine.py`
3. Add test cases in `tests/unit/test_your_check.py`
4. Document: what it scans, which OWASP/CWE/MITRE category it maps to

### New AI Provider
1. Create `ai/providers/your_provider.py` implementing `AIProvider` (see `ai/providers/base.py`)
2. Register it in `ai/provider_factory.py` `_build_provider()`
3. Add env var documentation to `.env.example`

### Bug Fix
1. Open an issue first for non-trivial changes
2. Write a failing test that reproduces the bug
3. Fix, ensure the test passes

## Pull Request Requirements

- [ ] Tests pass: `pytest tests/ -v`
- [ ] No new linting errors: `ruff check .`
- [ ] No new security issues: `bandit -r . -x venv,tests`
- [ ] `.env.example` updated if new env vars added
- [ ] PR description explains what was changed and why

## Coding Standards

- Python 3.11+, type hints on all public functions
- Every new `Finding` must have `vuln_type`, `severity`, `url`, `detail`, `evidence`, `remediation`
- `severity` must be one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- Reference the relevant CWE/OWASP/MITRE ID in the finding detail or docstring
- Do not commit `.env`, `*.db`, `__pycache__/`, or generated reports

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
All participants must adhere to its standards.

## Legal

All contributions must be for authorized security testing only.
By submitting a contribution you confirm that your code does not
enable unauthorized access to systems the user does not own or
have explicit written permission to test.
