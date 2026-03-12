# 🔐 Security Audit Checklist Tool

**Author:** Marcus Albright  
**Language:** Python 3  
**Level:** Entry-Level / Beginner  
**Framework Alignment:** NIST Cybersecurity Framework (CSF)

---

## 📋 Overview

A lightweight, beginner-friendly Python tool that performs automated security checks on a local system and generates a structured audit report. Built to demonstrate foundational cybersecurity concepts including vulnerability management, access control, data protection, and compliance documentation.

This project aligns with real-world security analyst responsibilities including:
- Security auditing and control validation
- NIST CSF framework application
- Risk identification and remediation recommendations
- Audit documentation and reporting

---

## 🔍 What It Checks

| Check | NIST CSF Ref | Description |
|---|---|---|
| OS Identification | PR.IP-1 | Detects OS type and recommends hardening baseline |
| Open Port Scan | PR.AC-3 | Scans localhost for open/risky ports |
| Environment Variable Scan | PR.DS-1 | Flags potentially sensitive variable names |
| Python Version Check | PR.IP-12 | Detects outdated/EOL runtime versions |
| Temp Directory Scan | PR.DS-3 | Looks for sensitive file types in temp folders |

---

## 🚀 How to Run

**Requirements:** Python 3.9+, no external libraries needed (uses standard library only)

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/security-audit-tool.git
cd security-audit-tool

# Run the audit
python security_audit.py
```

---

## 📊 Sample Output

```
=================================================================
         SECURITY AUDIT REPORT
=================================================================
  Auditor     : Marcus Albright
  Hostname    : DESKTOP-EXAMPLE
  OS          : Windows
  IP Address  : 192.168.1.10
  Audit Time  : 2025-09-01 14:32:00
  Score       : 8/10 (80%) — LOW RISK
=================================================================

[1] ✅ Operating System Identification
     Status : PASS
     Detail : Operating system detected: Windows
     Fix    : Ensure OS is fully patched and hardening guides are applied.
     NIST   : PR.IP-1

[2] ✅ Open Port Scan (Localhost)
     Status : PASS
     Detail : No commonly targeted ports detected as open on localhost.
     Fix    : Close or firewall any unused ports.
     NIST   : PR.AC-3
...
```

A full JSON report is saved automatically after each run.

---

## 🛠️ Built With

- Python 3 (standard library only — `os`, `socket`, `platform`, `json`, `datetime`)
- No external dependencies required

---

## 📁 Project Structure

```
security-audit-tool/
│
├── security_audit.py     # Main audit script
├── README.md             # Project documentation
└── sample_report.json    # Example JSON output
```

---

## 🔭 Future Enhancements

- [ ] Add password policy strength checker
- [ ] Add firewall status detection (Windows Defender / iptables)
- [ ] Add user account audit (detect accounts with no expiry)
- [ ] Export report to PDF
- [ ] Add scoring dashboard (HTML output)
- [ ] Integrate CVE lookup via NVD API

---

## 📚 Learning Resources Used

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- EC-Council Network Defense Essentials (NDE) — Certified Sep 2025
- University of Tennessee QuickStart Cybersecurity Bootcamp — May 2025

---

## 📄 License

MIT License — free to use, modify, and distribute.
