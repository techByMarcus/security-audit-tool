# Security Audit Tool

A small, read-only Python project for practicing host-security assessment and structured findings.

I built this project to work through a practical analyst workflow: collect limited host context, check a few high-signal conditions, document what was observed, and produce findings that can be reviewed instead of presenting a black-box "security score."

## What the tool checks

| Check | What it does | NIST CSF 2.0 context |
| --- | --- | --- |
| Platform context | Records the operating system and release for report context | PR.PS — Platform Security |
| Local service exposure | Reviews a short list of commonly sensitive localhost ports | PR.PS — Platform Security |
| Environment-variable secret indicators | Flags variable names that may contain secrets without collecting their values | PR.DS — Data Security |
| Python runtime baseline | Compares the running interpreter with the project's Python 3.10 minimum | PR.PS — Platform Security |
| Temporary-file review | Looks for a limited set of high-signal sensitive file extensions in temporary storage | PR.DS — Data Security |

The NIST references are contextual mappings to CSF 2.0 categories. They are not a claim that this script performs a CSF assessment or compliance certification.

## Why I changed the scoring model

Earlier versions assigned a numeric "risk score" to a very small number of local checks. That created more precision than the evidence supported.

The current version uses straightforward statuses instead:

- `PASS` — the specific condition checked was not observed
- `REVIEW` — something was found that needs analyst context
- `INFO` — contextual information, not a pass/fail security decision
- `ERROR` — the check could not complete

The report returns `REVIEW_REQUIRED` when at least one finding needs follow-up.

## Example

```text
[INFO] Platform Context
[PASS] Local Service Exposure
[REVIEW] Environment Variable Secret Indicators
[PASS] Python Runtime Baseline
[PASS] Temporary File Review

Overall status: REVIEW_REQUIRED
```

The environment-variable check records names only. Values are never written to the report.

## Quick start

Requirements: Python 3.10 or later. No third-party packages are required.

```bash
git clone https://github.com/techByMarcus/security-audit-tool.git
cd security-audit-tool

python security_audit.py --text
```

Write the JSON report to a custom path:

```bash
python security_audit.py --auditor "Marcus Albright" --output audit_report.json --text
```

Run without saving a report:

```bash
python security_audit.py --no-save --text
```

## Example JSON structure

```json
{
  "summary": {
    "overall_status": "REVIEW_REQUIRED",
    "counts": {
      "PASS": 3,
      "REVIEW": 1,
      "INFO": 1,
      "ERROR": 0
    },
    "scope_note": "Read-only baseline checks; results require analyst review and are not a compliance certification."
  }
}
```

See [`sample_report.json`](./sample_report.json) for a fuller example.

## Tests

The repository includes unit tests for:

- secret-value redaction
- environment-variable detection
- local-port outcomes
- temporary-file detection
- report generation
- overall-status logic
- local IP lookup fallback

Run them with:

```bash
python -m unittest discover -s tests -v
```

A GitHub Actions workflow runs the test suite on Python 3.10, 3.11, 3.12, and 3.13 for pull requests and changes to `main`.

## Repository structure

```text
security-audit-tool/
├── .github/
│   └── workflows/
│       └── tests.yml
├── tests/
│   └── test_security_audit.py
├── security_audit.py
├── sample_report.json
├── .gitignore
└── README.md
```

## Scope and limitations

This project is intentionally limited.

- It checks localhost only; it is not a network scanner.
- The port list is small and predefined.
- Environment-variable detection is based on variable names, not secret contents.
- Temporary-file review looks only at selected file extensions and does not inspect file contents.
- A `PASS` means only that the condition checked was not observed. It does not mean the host is secure.
- The tool does not replace vulnerability scanners, EDR, SIEM, patch management, hardening benchmarks, or a formal risk assessment.

## Training context

This project is part of my cybersecurity portfolio and reflects hands-on study in security operations, network defense, risk, and incident analysis.

Related work:

- [SOC Analyst Portfolio](https://github.com/techByMarcus/soc-analyst-portfolio)
- [Real-World Log Investigation](https://github.com/techByMarcus/real-world-log-investigation)
- [GRC Risk Assessment — Financial Services](https://github.com/techByMarcus/grc-risk-assessment-financial-services)
- [Portfolio](https://techbymarcus.github.io/aboutMarcus/)

NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
