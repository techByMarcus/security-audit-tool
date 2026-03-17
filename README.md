# 🔐 Security Audit Tool - Enhanced Edition

**Author:** Marcus Albright  
**Language:** Python 3.9+  
**Level:** Beginner → Intermediate  
**Framework:** NIST Cybersecurity Framework (CSF)

---

## 📋 Overview

A lightweight Python tool that performs automated security checks on your local system and generates detailed audit reports. Built to teach real cybersecurity concepts while building practical Python skills.

**What you'll learn building this:**
- Object-oriented Python (classes, methods)
- Error handling & safe operations
- CLI argument parsing
- JSON data structures & file I/O
- System interaction (sockets, environment, file system)
- Security best practices

---

## 🎯 What It Checks

| Check | NIST CSF | What It Does |
|-------|----------|-------------|
| **OS Identification** | PR.IP-1 | Detects OS type, version, and recommends hardening |
| **Open Ports** | PR.AC-3 | Scans for risky ports (FTP, RDP, SMB, etc.) |
| **Environment Variables** | PR.DS-1 | Flags sensitive variable names (passwords, tokens) |
| **Python Version** | PR.IP-12 | Checks if runtime is current & supported |
| **Temp Directory Scan** | PR.DS-3 | Looks for sensitive files in `/tmp` or `%TEMP%` |

---

## 🚀 Quick Start

### Requirements
- Python 3.9 or higher
- **No external dependencies** (uses Python standard library only)

### Installation
```bash
# Clone the repository
git clone https://github.com/techByMarcus/security-audit-tool.git
cd security-audit-tool

# Verify Python version
python --version
# Should output: Python 3.9.x or higher
```

### Basic Usage
```bash
# Run default audit
python security_audit.py

# Run with custom auditor name
python security_audit.py --auditor "Marcus Albright"

# Print text report to console
python security_audit.py --text

# Save report and print text report
python security_audit.py --output my_audit.json --text

# Run audit without saving JSON file
python security_audit.py --no-save --text
```

### Example Output
```
🔍 Running security checks...

✅ Operating System Identification: PASS
✅ Open Port Scan (Localhost): PASS
⚠️  Environment Variable Scan: WARN
✅ Python Version Check: PASS
✅ Temporary Directory Scan: PASS

📊 Audit Complete: 8.2/10 — LOW RISK
✅ Report saved to: security_audit_report.json
```

---

## 📊 Sample Report Output

### Console (Text Format)
```
================================================================================
                        SECURITY AUDIT REPORT
================================================================================

Auditor:        Marcus Albright
Hostname:       DESKTOP-EXAMPLE
OS:             Windows 10
IP Address:     192.168.1.100
Audit Time:     2025-03-16 14:32:00
Python:         3.11.5

Score:          8.2/10 — LOW RISK
Checks Run:     5 (Passed: 4, Failed: 1)
================================================================================

[1] Operating System Identification
    Status:     PASS
    Detail:     OS: Windows 10
    Fix:        Ensure OS is fully patched and hardening guides are applied.
    NIST CSF:   PR.IP-1
    Severity:   INFO

[2] Open Port Scan (Localhost)
    Status:     PASS
    Detail:     No commonly targeted ports detected as open on localhost.
    Fix:        Close or firewall any unnecessary ports.
    NIST CSF:   PR.AC-3
    Severity:   INFO
```

### JSON Report (`security_audit_report.json`)
```json
{
  "audit_metadata": {
    "auditor": "Marcus Albright",
    "hostname": "DESKTOP-EXAMPLE",
    "os": "Windows",
    "ip_address": "192.168.1.100",
    "audit_time": "2025-03-16 14:32:00",
    "python_version": "3.11.5"
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

## 🛠️ Project Structure
```
security-audit-tool/
├── security_audit.py          # Main audit script (~450 lines, well-commented)
├── README.md                  # This file
├── sample_report.json         # Example JSON output
└── .gitignore                 # (Optional) Exclude report files from git
```

### `.gitignore` (Recommended)
```
# Ignore generated reports
security_audit_report*.json
*.json.bak

# Ignore Python cache
__pycache__/
*.pyc
*.pyo
*.egg-info/
.pytest_cache/

# IDE
.vscode/
.idea/
*.swp
```

---

## 📚 Python Learning Points

### Key Concepts Demonstrated

#### 1. **Object-Oriented Programming (Classes)**
```python
class SecurityAudit:
    """Encapsulates audit logic and state"""
    def __init__(self, auditor_name: str = "Tool"):
        self.auditor_name = auditor_name
        self.findings = []
    
    def check_os_identification(self):
        # Methods perform specific tasks
        pass
```

#### 2. **Type Hints** (Python 3.5+)
```python
def calculate_risk_score(self) -> Tuple[int, str]:
    """Return type shows: int score + str risk_level"""
    return round(score, 1), risk_level
```

#### 3. **Error Handling with Try/Except**
```python
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(("127.0.0.1", port))
except Exception as e:
    print(f"Error: {e}")
```

#### 4. **Dictionary & List Operations**
```python
findings = {
    "check_number": 1,
    "status": "PASS",
    "detail": "..."
}

json_string = json.dumps(findings, indent=2)
```

#### 5. **Command-Line Arguments (argparse)**
```python
parser = argparse.ArgumentParser()
parser.add_argument("--auditor", type=str, default="Tool")
args = parser.parse_args()
```

#### 6. **File Operations**
```python
# Safe file writing
with open(filename, "w") as f:
    f.write(content)
```

---

## 🎓 Learning Resources

### Certifications Completed
- EC-Council Network Defense Essentials (NDE-112-51) — Sep 2025
- University of Tennessee QuickStart Cybersecurity Bootcamp — May 2025
- AWS Cloud Technical Essentials — Aug 2025

### Python Resources
- **Official Python Docs:** https://docs.python.org/3/
- **Type Hints:** https://docs.python.org/3/library/typing.html
- **Standard Library Reference:** https://docs.python.org/3/library/

### Cybersecurity Resources
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework
- **CIS Benchmarks:** https://www.cisecurity.org/cis-benchmarks/
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/

---

## 🛡️ Security Notes

### What This Tool Does NOT Do
- ❌ Network penetration testing
- ❌ Malware scanning
- ❌ Log analysis
- ❌ Replace professional security assessments

### Safe Operations
- ✅ Only scans localhost (127.0.0.1) — no external scanning
- ✅ Reads-only from `/tmp` and `%TEMP%` — no modifications
- ✅ No external dependencies — less attack surface
- ✅ Redacts sensitive values in reports
- ✅ Standard library only — trusted source

---

## 📄 License

MIT License — Free to use, modify, and distribute.

**Attribution:** If you use this code, please credit Marcus Albright.

---

**Happy learning! 🎓**

*Last updated: March 2025*  
*Python version: 3.9+*  
*Status: Production-ready & Educational*
```

---

After you paste it, **commit with message:**
```
Update: Enhanced README with usage examples, learning points, and NIST alignment
