#!/usr/bin/env python3
"""
Security Audit Tool - Enhanced Version
Author: Marcus Albright
Purpose: Automated local system security checks with structured reporting
Framework: NIST Cybersecurity Framework (CSF)
Python Level: Beginner with intermediate practices
"""

import os
import socket
import platform
import json
import sys
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple


class SecurityAudit:
    """
    Main audit class that encapsulates all security checks.
    Using a class helps organize related functions and maintain state.
    """

    def __init__(self, auditor_name: str = "Security Audit Tool"):
        """
        Initialize the audit with metadata.
        
        Args:
            auditor_name: Name of the auditor running the checks
        """
        self.auditor_name = auditor_name
        self.hostname = socket.gethostname()
        self.ip_address = self._get_ip_address()
        self.os_type = platform.system()
        self.audit_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.checks_passed = 0
        self.checks_failed = 0
        self.findings = []

    def _get_ip_address(self) -> str:
        """
        Safely retrieve local IP address.
        Uses socket to connect without sending data (no external traffic).
        
        Returns:
            IP address string or 'UNKNOWN' if retrieval fails
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            print(f"⚠️  Warning: Could not determine IP address: {e}")
            return "UNKNOWN"

    def check_os_identification(self) -> Dict:
        """
        Check 1: Identify operating system and version.
        NIST CSF Reference: PR.IP-1 (Information Protection Processes)
        
        Returns:
            Dictionary with check results
        """
        try:
            os_info = f"{self.os_type} {platform.release()}"
            
            recommendations = {
                "Windows": "Run Windows Update, enable Windows Defender, configure Windows Firewall",
                "Linux": "Keep packages updated (apt/yum), harden SSH config, configure UFW/iptables",
                "Darwin": "Keep macOS updated, enable FileVault encryption, configure built-in firewall"
            }
            
            fix = recommendations.get(self.os_type, "Ensure OS is patched and hardening guides applied")
            
            result = {
                "check_number": 1,
                "name": "Operating System Identification",
                "status": "PASS",
                "detail": f"OS: {os_info}",
                "fix": fix,
                "nist_ref": "PR.IP-1",
                "severity": "INFO"
            }
            self.checks_passed += 1
            return result
            
        except Exception as e:
            return {
                "check_number": 1,
                "name": "Operating System Identification",
                "status": "FAIL",
                "detail": str(e),
                "fix": "Review system configuration",
                "nist_ref": "PR.IP-1",
                "severity": "HIGH"
            }

    def check_open_ports(self) -> Dict:
        """
        Check 2: Scan localhost for open/risky ports.
        NIST CSF Reference: PR.AC-3 (Access Control)
        
        Common risky ports: 21 (FTP), 23 (Telnet), 445 (SMB), 3389 (RDP)
        
        Returns:
            Dictionary with check results
        """
        risky_ports = {
            21: "FTP (unencrypted file transfer)",
            23: "Telnet (unencrypted remote shell)",
            445: "SMB (Windows file sharing - common attack vector)",
            3389: "RDP (Remote Desktop Protocol - brute force target)",
            5985: "WinRM (Windows Remote Management)",
            27017: "MongoDB (NoSQL database - should not be exposed)",
            6379: "Redis (in-memory cache - often unsecured)"
        }
        
        open_risky_ports = []
        
        for port, service_name in risky_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex(("127.0.0.1", port))
                sock.close()
                
                if result == 0:
                    open_risky_ports.append(f"Port {port} ({service_name})")
                    
            except Exception as e:
                pass
        
        if open_risky_ports:
            status = "FAIL"
            detail = f"Found open risky ports: {', '.join(open_risky_ports)}"
            self.checks_failed += 1
            severity = "CRITICAL"
        else:
            status = "PASS"
            detail = "No commonly targeted ports detected as open on localhost"
            self.checks_passed += 1
            severity = "INFO"
        
        return {
            "check_number": 2,
            "name": "Open Port Scan (Localhost)",
            "status": status,
            "detail": detail,
            "fix": "Close or firewall any unnecessary ports. Use 'netstat -an' (Windows) or 'ss -tuln' (Linux) to review",
            "nist_ref": "PR.AC-3",
            "severity": severity
        }

    def check_environment_variables(self) -> Dict:
        """
        Check 3: Scan environment variables for sensitive names.
        NIST CSF Reference: PR.DS-1 (Data Security)
        
        Returns:
            Dictionary with check results
        """
        sensitive_keywords = [
            "password", "passwd", "pwd", "secret", "token", "api_key",
            "apikey", "private_key", "private-key", "aws_secret",
            "db_password", "database_password", "oauth"
        ]
        
        suspicious_vars = []
        
        for var_name, var_value in os.environ.items():
            if any(keyword in var_name.lower() for keyword in sensitive_keywords):
                suspicious_vars.append(f"{var_name}=***REDACTED***")
        
        if suspicious_vars:
            status = "WARN"
            detail = f"Found {len(suspicious_vars)} environment variable(s) with sensitive names: {', '.join(suspicious_vars[:3])}"
            self.checks_failed += 1
            severity = "MEDIUM"
        else:
            status = "PASS"
            detail = "No obviously sensitive environment variables detected"
            self.checks_passed += 1
            severity = "INFO"
        
        return {
            "check_number": 3,
            "name": "Environment Variable Scan",
            "status": status,
            "detail": detail,
            "fix": "Use secret management tools (HashiCorp Vault, AWS Secrets Manager) instead of env vars for production",
            "nist_ref": "PR.DS-1",
            "severity": severity
        }

    def check_python_version(self) -> Dict:
        """
        Check 4: Verify Python version is current and supported.
        NIST CSF Reference: PR.IP-12 (Security Configuration Management)
        
        Returns:
            Dictionary with check results
        """
        python_version = platform.python_version()
        version_tuple = sys.version_info
        
        supported_versions = [(3, 9), (3, 10), (3, 11), (3, 12)]
        current_version = (version_tuple.major, version_tuple.minor)
        
        if current_version in supported_versions:
            status = "PASS"
            detail = f"Python {python_version} is currently supported"
            self.checks_passed += 1
            severity = "INFO"
        else:
            status = "FAIL" if current_version < (3, 9) else "WARN"
            detail = f"Python {python_version} may be outdated or unsupported"
            if status == "FAIL":
                self.checks_failed += 1
            severity = "MEDIUM"
        
        return {
            "check_number": 4,
            "name": "Python Version Check",
            "status": status,
            "detail": detail,
            "fix": f"Upgrade to Python 3.10 or later. Current: {python_version}",
            "nist_ref": "PR.IP-12",
            "severity": severity
        }

    def check_temp_directory(self) -> Dict:
        """
        Check 5: Scan temporary directories for sensitive files.
        NIST CSF Reference: PR.DS-3 (Data Protection in Transit)
        
        Returns:
            Dictionary with check results
        """
        sensitive_extensions = [
            ".key", ".pem", ".p12", ".pfx",
            ".sql", ".db",
            ".env", ".conf",
            ".txt", ".log"
        ]
        
        temp_dirs = []
        if self.os_type == "Windows":
            temp_dirs = [os.environ.get("TEMP", "C:\\Temp")]
        else:
            temp_dirs = ["/tmp", os.path.expanduser("~/.tmp")]
        
        suspicious_files = []
        
        for temp_dir in temp_dirs:
            if not os.path.exists(temp_dir):
                continue
            
            try:
                for root, dirs, files in os.walk(temp_dir):
                    if root.count(os.sep) - temp_dir.count(os.sep) > 2:
                        dirs.clear()
                        continue
                    
                    for file in files[:50]:
                        if any(file.endswith(ext) for ext in sensitive_extensions):
                            rel_path = os.path.relpath(os.path.join(root, file), temp_dir)
                            suspicious_files.append(rel_path)
                            
            except PermissionError:
                pass
        
        if suspicious_files:
            status = "WARN"
            detail = f"Found {len(suspicious_files)} potentially sensitive file(s) in temp directories"
            self.checks_failed += 1
            severity = "MEDIUM"
        else:
            status = "PASS"
            detail = "No obviously sensitive files detected in temp directories"
            self.checks_passed += 1
            severity = "INFO"
        
        return {
            "check_number": 5,
            "name": "Temporary Directory Scan",
            "status": status,
            "detail": detail,
            "fix": "Regularly clean temp directories. Use 'Disk Cleanup' (Windows) or 'rm -rf /tmp/*' (Linux)",
            "nist_ref": "PR.DS-3",
            "severity": severity
        }

    def calculate_risk_score(self) -> Tuple[int, str]:
        """
        Calculate overall risk score based on check results.
        
        Scoring: 
        - Each passed check = +20 points (5 checks total)
        - Each failed/warning = -10 points per issue
        
        Returns:
            Tuple of (score out of 10, risk_level_string)
        """
        total_checks = self.checks_passed + self.checks_failed
        if total_checks == 0:
            return 5, "UNKNOWN"
        
        score = (self.checks_passed / total_checks) * 10
        
        if score >= 8:
            risk_level = "LOW RISK"
        elif score >= 6:
            risk_level = "MEDIUM RISK"
        elif score >= 4:
            risk_level = "HIGH RISK"
        else:
            risk_level = "CRITICAL RISK"
        
        return round(score, 1), risk_level

    def run_all_checks(self) -> List[Dict]:
        """
        Execute all security checks in sequence.
        
        Returns:
            List of check results
        """
        print("🔍 Running security checks...\n")
        
        checks = [
            self.check_os_identification,
            self.check_open_ports,
            self.check_environment_variables,
            self.check_python_version,
            self.check_temp_directory
        ]
        
        for check_func in checks:
            result = check_func()
            self.findings.append(result)
            status_emoji = "✅" if result["status"] == "PASS" else "⚠️ " if result["status"] == "WARN" else "❌"
            print(f"{status_emoji} {result['name']}: {result['status']}")
        
        return self.findings

    def generate_report(self, output_format: str = "json") -> str:
        """
        Generate audit report in specified format.
        
        Args:
            output_format: "json", "text", or "both"
            
        Returns:
            Report as string
        """
        score, risk_level = self.calculate_risk_score()
        
        report_data = {
            "audit_metadata": {
                "auditor": self.auditor_name,
                "hostname": self.hostname,
                "os": self.os_type,
                "ip_address": self.ip_address,
                "audit_time": self.audit_time,
                "python_version": platform.python_version()
            },
            "audit_summary": {
                "total_checks": len(self.findings),
                "passed": self.checks_passed,
                "failed": self.checks_failed,
                "risk_score": f"{score}/10",
                "risk_level": risk_level
            },
            "findings": self.findings
        }
        
        if output_format == "json":
            return json.dumps(report_data, indent=2)
        elif output_format == "text":
            return self._format_text_report(report_data)
        else:
            return json.dumps(report_data, indent=2)

    def _format_text_report(self, report_data: Dict) -> str:
        """Format report as readable text."""
        lines = []
        lines.append("=" * 80)
        lines.append("SECURITY AUDIT REPORT".center(80))
        lines.append("=" * 80)
        lines.append("")
        
        metadata = report_data["audit_metadata"]
        lines.append(f"Auditor:        {metadata['auditor']}")
        lines.append(f"Hostname:       {metadata['hostname']}")
        lines.append(f"OS:             {metadata['os']}")
        lines.append(f"IP Address:     {metadata['ip_address']}")
        lines.append(f"Audit Time:     {metadata['audit_time']}")
        lines.append(f"Python:         {metadata['python_version']}")
        lines.append("")
        
        summary = report_data["audit_summary"]
        lines.append(f"Score:          {summary['risk_score']} — {summary['risk_level']}")
        lines.append(f"Checks Run:     {summary['total_checks']} (Passed: {summary['passed']}, Failed: {summary['failed']})")
        lines.append("=" * 80)
        lines.append("")
        
        for finding in report_data["findings"]:
            lines.append(f"[{finding['check_number']}] {finding['name']}")
            lines.append(f"    Status:     {finding['status']}")
            lines.append(f"    Detail:     {finding['detail']}")
            lines.append(f"    Fix:        {finding['fix']}")
            lines.append(f"    NIST CSF:   {finding['nist_ref']}")
            lines.append(f"    Severity:   {finding['severity']}")
            lines.append("")
        
        return "\n".join(lines)

    def save_report(self, filename: str, output_format: str = "json"):
        """
        Save report to file.
        
        Args:
            filename: Output filename
            output_format: "json" or "text"
        """
        report_content = self.generate_report(output_format)
        
        try:
            with open(filename, "w") as f:
                f.write(report_content)
            print(f"✅ Report saved to: {filename}")
        except Exception as e:
            print(f"❌ Error saving report: {e}")


def main():
    """Main entry point with CLI argument support."""
    parser = argparse.ArgumentParser(
        description="Security Audit Tool - Automated local system security checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_audit.py                    # Run audit, save JSON report
  python security_audit.py --auditor "Jane"   # Custom auditor name
  python security_audit.py --text             # Print text report only
  python security_audit.py --output audit.json --text  # Save JSON and print text
        """
    )
    
    parser.add_argument(
        "--auditor",
        type=str,
        default="Security Audit Tool",
        help="Name of the auditor (default: Security Audit Tool)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="security_audit_report.json",
        help="Output filename for JSON report (default: security_audit_report.json)"
    )
    parser.add_argument(
        "--text",
        action="store_true",
        help="Print text-formatted report to console"
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Don't save JSON report to file"
    )
    
    args = parser.parse_args()
    
    # Create audit instance and run
    audit = SecurityAudit(auditor_name=args.auditor)
    audit.run_all_checks()
    
    # Display text report if requested
    if args.text:
        print("\n" + audit.generate_report("text"))
    
    # Save JSON report unless disabled
    if not args.no_save:
        audit.save_report(args.output, "json")
    
    # Print summary
    score, risk_level = audit.calculate_risk_score()
    print(f"\n📊 Audit Complete: {score}/10 — {risk_level}")


if __name__ == "__main__":
    main()
```

---

After you paste it, click **"Commit changes"** and write a commit message like:
```
Refactor: Enhanced security audit tool with OOP architecture and CLI

- Convert to class-based SecurityAudit architecture
- Add type hints throughout
- Implement argparse CLI with 4 options
- Add comprehensive error handling
- Improve reporting (JSON + text formats)
- Add risk scoring and severity levels
- Add inline comments for learning
