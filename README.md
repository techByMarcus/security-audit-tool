# Security Audit Tool

**Author:** Marcus Albright  
**Language:** Python 3.9+  
**Framework Alignment:** NIST Cybersecurity Framework (CSF)  
**Status:** Production-ready

---

## Overview

A Python-based automated security audit tool that performs structured system security checks and generates risk-scored findings reports — aligned to NIST CSF controls. Designed to surface actionable security posture data in environments where manual audits are time-intensive or inconsistently applied.

This tool reflects the same structured, evidence-based approach used in professional GRC and security operations work: define the control, test the condition, document the finding, assign a risk rating, recommend a fix.

---

## What It Audits

| Check | NIST CSF Reference | Risk Area |
|---|---|---|
| OS Identification & Patch Status | PR.IP-1 | Asset Management |
| Open Port Exposure (Localhost) | PR.AC-3 | Access Control |
| Sensitive Environment Variables | PR.DS-1 | Data Security |
| Python Runtime Currency | PR.IP-12 | Vulnerability Management |
| Temporary Directory Contents | PR.DS-3 | Data Protection |

Each check produces a structured finding with: status, detail, remediation guidance, NIST CSF reference, and severity rating.

---

## Output

The tool generates a **risk-scored audit report** in both JSON and console formats:

```
Score:      8.2 / 10 — LOW RISK
Checks Run: 5  (Passed: 4 / Warnings: 1 / Failed: 0)
```

**JSON report structure:**
```json
{
  "audit_metadata": {
    "auditor": "Marcus Albright",
    "hostname": "DESKTOP-EXAMPLE",
    "os": "Windows 10",
    "audit_time": "2025-03-16 14:32:00"
  },
  "audit_summary": {
    "total_checks": 5,
    "passed": 4,
    "failed": 1,
    "risk_score": "8.2/10",
    "risk_level": "LOW RISK"
  },
  "findings": [
    {
      "check_number": 1,
      "name": "Operating System Identification",
      "status": "PASS",
      "detail": "OS: Windows 10",
      "fix": "Ensure OS is fully patched and hardening guides are applied.",
      "nist_ref": "PR.IP-1",
      "severity": "INFO"
    }
  ]
}
```

---

## Quick Start

**Requirements:** Python 3.9+ · No external dependencies

```bash
# Clone
git clone https://github.com/techByMarcus/security-audit-tool.git
cd security-audit-tool

# Run default audit
python security_audit.py

# Run with auditor name, output to file, print to console
python security_audit.py --auditor "Marcus Albright" --output audit_report.json --text

# Console output only — no file saved
python security_audit.py --no-save --text
```

---

## Design Notes

- **Localhost-only scanning** — no external network calls; safe to run in any environment
- **Read-only operations** — no modifications to system files or directories
- **No external dependencies** — standard Python library only; minimal attack surface
- **Sensitive value redaction** — environment variable values are never written to reports
- **Structured output** — JSON reports are designed for downstream ingestion or integration with SIEM tooling

---

## Repository Structure

```
security-audit-tool/
├── security_audit.py       # Main audit engine (~450 lines)
├── sample_report.json      # Example JSON output
└── README.md
```

---

## Certifications & Framework Context

This tool was built in parallel with formal security training and reflects applied knowledge from:

- University of Tennessee QuickStart Cybersecurity Bootcamp — May 2025
- EC-Council Network Defense Essentials (NDE) — 2025
- EC-Council Ethical Hacking Essentials (EHE) — 2025
- NIST Cybersecurity Framework (CSF) — applied study

NIST CSF reference: [https://www.nist.gov/cyberframework](https://www.nist.gov/cyberframework)

---

## Related Portfolio Work

| Project | Description |
|---|---|
| [GRC Risk Assessment — Mortgage Lending](https://github.com/techByMarcus/grc-risk-assessment-financial-services) | NIST CSF applied to a regulated financial-services workflow — risk register, gap analysis, remediation roadmap |
| [SOC Analyst Portfolio](https://github.com/techByMarcus/soc-analyst-portfolio) | 20+ incident investigations — alert triage, MITRE ATT&CK mapping, structured findings reports |
| [Real-World Log Investigation](https://github.com/techByMarcus/real-world-log-investigation) | Account compromise simulation — authentication log analysis, attack timeline reconstruction, IOC identification |

---

*Marcus Albright · [LinkedIn](https://www.linkedin.com/in/marcus-a-69ab2989) · [Portfolio](https://techbymarcus.github.io/aboutMarcus)*
