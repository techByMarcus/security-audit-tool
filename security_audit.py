"""
=============================================================
  Security Audit Checklist Tool
  Author: Marcus Albright
  Description: A beginner-friendly Python tool that performs
               basic security checks on a system and generates
               a structured audit report. Aligned with NIST
               Cybersecurity Framework controls.
=============================================================
"""

import os
import platform
import socket
import datetime
import json

# ─────────────────────────────────────────────
# SECTION 1: SYSTEM INFORMATION
# Gather basic info about the machine being audited
# ─────────────────────────────────────────────

def get_system_info():
    """Collect basic operating system and network information."""
    print("[*] Gathering system information...")

    info = {
        "hostname":       socket.gethostname(),
        "os":             platform.system(),
        "os_version":     platform.version(),
        "architecture":   platform.machine(),
        "audit_time":     datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "auditor":        "Marcus Albright"
    }

    # Try to get the local IP address
    try:
        info["ip_address"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        info["ip_address"] = "Unable to retrieve"

    return info


# ─────────────────────────────────────────────
# SECTION 2: SECURITY CHECKS
# Each function below checks one security control.
# Returns a dict with: check name, status, and recommendation.
# ─────────────────────────────────────────────

def check_os_type():
    """
    Identify the operating system.
    Different OS types have different hardening requirements.
    NIST CSF Reference: PR.IP-1 (Baseline configuration)
    """
    os_name = platform.system()

    if os_name in ["Windows", "Linux", "Darwin"]:
        status = "INFO"
        detail = f"Operating system detected: {os_name}"
        recommendation = "Ensure OS is fully patched and hardening guides are applied (CIS Benchmarks recommended)."
    else:
        status = "WARNING"
        detail = f"Unrecognized OS: {os_name}"
        recommendation = "Verify OS identity and apply appropriate security baseline."

    return {
        "check":          "Operating System Identification",
        "status":         status,
        "detail":         detail,
        "recommendation": recommendation,
        "nist_ref":       "PR.IP-1"
    }


def check_open_ports():
    """
    Scan common ports on localhost to detect open services.
    Open ports = potential attack surface.
    NIST CSF Reference: PR.AC-3 (Remote access management)
    """
    print("[*] Checking open ports (this may take a moment)...")

    # List of common ports to check
    # In a real SOC environment, tools like Nmap would be used
    common_ports = {
        21:   "FTP",
        22:   "SSH",
        23:   "Telnet",
        25:   "SMTP",
        80:   "HTTP",
        443:  "HTTPS",
        3306: "MySQL",
        3389: "RDP (Remote Desktop)",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate"
    }

    open_ports   = []
    risky_ports  = [21, 23, 3389]  # These ports are commonly exploited

    for port, service in common_ports.items():
        try:
            # Create a socket and attempt connection
            # timeout=0.5 means we wait 0.5 seconds before giving up
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(("127.0.0.1", port))
            sock.close()

            if result == 0:  # 0 means the port is open
                risk = "HIGH RISK" if port in risky_ports else "OPEN"
                open_ports.append(f"Port {port} ({service}) - {risk}")
        except Exception:
            pass  # If we can't check the port, skip it

    if not open_ports:
        status = "PASS"
        detail = "No commonly targeted ports detected as open on localhost."
    elif any("HIGH RISK" in p for p in open_ports):
        status = "FAIL"
        detail = f"High-risk ports detected: {', '.join(open_ports)}"
    else:
        status = "WARNING"
        detail = f"Open ports found: {', '.join(open_ports)}"

    return {
        "check":          "Open Port Scan (Localhost)",
        "status":         status,
        "detail":         detail,
        "recommendation": "Close or firewall any unused ports. Disable Telnet (port 23) immediately — it transmits data unencrypted.",
        "nist_ref":       "PR.AC-3"
    }


def check_environment_variables():
    """
    Check if sensitive data is stored in environment variables.
    Developers sometimes accidentally store passwords/keys here.
    NIST CSF Reference: PR.DS-1 (Data-at-rest protection)
    """
    print("[*] Scanning environment variables for sensitive data...")

    # Keywords that suggest sensitive data
    sensitive_keywords = [
        "password", "passwd", "secret", "api_key", "apikey",
        "token", "private_key", "aws_secret", "db_pass"
    ]

    flagged_vars = []

    for var_name in os.environ:
        # Check if the variable name contains a sensitive keyword
        var_lower = var_name.lower()
        for keyword in sensitive_keywords:
            if keyword in var_lower:
                # We flag the name but NEVER print the value (security best practice)
                flagged_vars.append(var_name)
                break

    if not flagged_vars:
        status = "PASS"
        detail = "No obviously sensitive variable names detected in environment."
    else:
        status = "WARNING"
        detail = f"Potentially sensitive environment variables found: {', '.join(flagged_vars)}"

    return {
        "check":          "Environment Variable Sensitivity Scan",
        "status":         status,
        "detail":         detail,
        "recommendation": "Never store passwords or API keys in environment variables in production. Use a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
        "nist_ref":       "PR.DS-1"
    }


def check_python_version():
    """
    Verify Python version is current and supported.
    Outdated software versions contain known vulnerabilities (CVEs).
    NIST CSF Reference: PR.IP-12 (Vulnerability management)
    """
    print("[*] Checking Python version...")

    version     = platform.python_version()
    major, minor, patch = [int(x) for x in version.split(".")]

    # Python 3.8 and below are end-of-life (no longer receive security patches)
    if major == 3 and minor >= 9:
        status = "PASS"
        detail = f"Python {version} is current and supported."
    elif major == 3 and minor == 8:
        status = "WARNING"
        detail = f"Python {version} is approaching end-of-life."
    else:
        status = "FAIL"
        detail = f"Python {version} is end-of-life and no longer receives security patches."

    return {
        "check":          "Python Runtime Version Check",
        "status":         status,
        "detail":         detail,
        "recommendation": "Always run supported software versions. Check python.org/downloads for the latest stable release.",
        "nist_ref":       "PR.IP-12"
    }


def check_temp_files():
    """
    Look for potentially sensitive files left in the temp directory.
    Attackers sometimes look for forgotten credentials or config files here.
    NIST CSF Reference: PR.DS-3 (Asset management)
    """
    print("[*] Scanning temp directory for sensitive file types...")

    # Identify the temp directory based on OS
    if platform.system() == "Windows":
        temp_dir = os.environ.get("TEMP", "C:\\Windows\\Temp")
    else:
        temp_dir = "/tmp"

    # File extensions that could contain sensitive data
    sensitive_extensions = [".key", ".pem", ".env", ".cfg", ".config", ".password", ".secret"]

    flagged_files = []

    try:
        for filename in os.listdir(temp_dir):
            for ext in sensitive_extensions:
                if filename.lower().endswith(ext):
                    flagged_files.append(filename)
    except PermissionError:
        return {
            "check":          "Temp Directory Sensitive File Scan",
            "status":         "INFO",
            "detail":         f"Permission denied accessing {temp_dir}. Manual review recommended.",
            "recommendation": "Ensure temp directories are regularly cleared and access is restricted.",
            "nist_ref":       "PR.DS-3"
        }

    if not flagged_files:
        status = "PASS"
        detail = f"No sensitive file types found in {temp_dir}."
    else:
        status = "WARNING"
        detail = f"Potentially sensitive files in temp dir: {', '.join(flagged_files)}"

    return {
        "check":          "Temp Directory Sensitive File Scan",
        "status":         status,
        "detail":         detail,
        "recommendation": "Regularly clear temp directories. Never store credentials or keys in temp folders.",
        "nist_ref":       "PR.DS-3"
    }


# ─────────────────────────────────────────────
# SECTION 3: REPORT GENERATION
# Takes all results and produces a clean report
# ─────────────────────────────────────────────

def calculate_score(results):
    """
    Calculate a simple security score based on check outcomes.
    PASS = 2 pts, WARNING = 1 pt, FAIL = 0 pts, INFO = 1 pt
    """
    scoring = {"PASS": 2, "WARNING": 1, "FAIL": 0, "INFO": 1}
    total_possible = len(results) * 2
    earned = sum(scoring.get(r["status"], 0) for r in results)
    percentage = round((earned / total_possible) * 100)
    return earned, total_possible, percentage


def generate_report(system_info, results):
    """Build and print the final audit report to the console and save as JSON."""

    earned, total, percentage = calculate_score(results)

    # Determine overall risk rating
    if percentage >= 80:
        risk_rating = "LOW RISK"
    elif percentage >= 50:
        risk_rating = "MEDIUM RISK"
    else:
        risk_rating = "HIGH RISK"

    # ── Console Report ──────────────────────────
    print("\n")
    print("=" * 65)
    print("         SECURITY AUDIT REPORT")
    print("=" * 65)
    print(f"  Auditor     : {system_info['auditor']}")
    print(f"  Hostname    : {system_info['hostname']}")
    print(f"  OS          : {system_info['os']} {system_info['os_version'][:40]}")
    print(f"  IP Address  : {system_info['ip_address']}")
    print(f"  Audit Time  : {system_info['audit_time']}")
    print(f"  Score       : {earned}/{total} ({percentage}%) — {risk_rating}")
    print("=" * 65)

    # Status icons for readability
    icons = {"PASS": "✅", "WARNING": "⚠️ ", "FAIL": "❌", "INFO": "ℹ️ "}

    for i, result in enumerate(results, 1):
        icon = icons.get(result["status"], "•")
        print(f"\n[{i}] {icon} {result['check']}")
        print(f"     Status : {result['status']}")
        print(f"     Detail : {result['detail']}")
        print(f"     Fix    : {result['recommendation']}")
        print(f"     NIST   : {result['nist_ref']}")

    print("\n" + "=" * 65)
    print("  SUMMARY")
    print("=" * 65)
    pass_count    = sum(1 for r in results if r["status"] == "PASS")
    warning_count = sum(1 for r in results if r["status"] == "WARNING")
    fail_count    = sum(1 for r in results if r["status"] == "FAIL")
    print(f"  ✅ Passed  : {pass_count}")
    print(f"  ⚠️  Warnings: {warning_count}")
    print(f"  ❌ Failed  : {fail_count}")
    print(f"\n  Overall Risk: {risk_rating}")
    print("=" * 65)

    # ── Save JSON Report ────────────────────────
    report_data = {
        "system_info": system_info,
        "score": {"earned": earned, "total": total, "percentage": percentage, "risk_rating": risk_rating},
        "results": results
    }

    report_filename = f"audit_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_filename, "w") as f:
        json.dump(report_data, f, indent=4)

    print(f"\n  📄 Full report saved to: {report_filename}")
    print("=" * 65)


# ─────────────────────────────────────────────
# SECTION 4: MAIN — Run the audit
# ─────────────────────────────────────────────

def run_audit():
    """Main function — runs all checks and generates the report."""

    print("\n" + "=" * 65)
    print("  Starting Security Audit...")
    print("  Author: Marcus Albright | NIST CSF Aligned")
    print("=" * 65 + "\n")

    # Step 1: Collect system info
    system_info = get_system_info()

    # Step 2: Run each security check
    # Add new check functions here as you expand the tool
    checks = [
        check_os_type,
        check_open_ports,
        check_environment_variables,
        check_python_version,
        check_temp_files,
    ]

    results = []
    for check_fn in checks:
        result = check_fn()
        results.append(result)

    # Step 3: Generate the report
    generate_report(system_info, results)


# Python entry point — only runs if this file is executed directly
if __name__ == "__main__":
    run_audit()
