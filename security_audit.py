#!/usr/bin/env python3
"""
Security Audit Tool
Author: Marcus Albright

A read-only local assessment utility for a small set of host-security checks.
This is a portfolio and learning project, not a replacement for enterprise
vulnerability management or compliance tooling.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


@dataclass
class Finding:
    name: str
    status: str
    severity: str
    detail: str
    recommendation: str
    csf_category: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class SecurityAudit:
    """Run a limited set of read-only local host checks."""

    RISKY_LOCAL_PORTS = {
        21: "FTP",
        23: "Telnet",
        445: "SMB",
        3389: "RDP",
        5985: "WinRM",
        27017: "MongoDB",
        6379: "Redis",
    }

    SECRET_NAME_HINTS = (
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "private-key",
        "aws_secret",
        "db_password",
        "database_password",
        "oauth",
    )

    HIGH_SIGNAL_TEMP_EXTENSIONS = {
        ".key",
        ".pem",
        ".p12",
        ".pfx",
        ".env",
        ".kdbx",
        ".ovpn",
    }

    MINIMUM_PYTHON = (3, 10)

    def __init__(
        self,
        auditor_name: str = "Security Audit Tool",
        temp_dirs: Iterable[str | Path] | None = None,
    ) -> None:
        self.auditor_name = auditor_name
        self.hostname = socket.gethostname()
        self.local_ip = self._get_local_ip()
        self.os_name = platform.system()
        self.os_release = platform.release()
        self.audit_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.temp_dirs = (
            [Path(p) for p in temp_dirs]
            if temp_dirs is not None
            else self._default_temp_dirs()
        )
        self.findings: list[Finding] = []

    @staticmethod
    def _get_local_ip() -> str:
        """Resolve the local hostname without contacting an external service."""
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "UNKNOWN"

    def _default_temp_dirs(self) -> list[Path]:
        paths = [Path(tempfile.gettempdir())]
        if self.os_name != "Windows":
            user_tmp = Path.home() / ".tmp"
            if user_tmp != paths[0]:
                paths.append(user_tmp)
        return paths

    def check_platform_context(self) -> Finding:
        """Record operating-system context without treating detection as a security pass."""
        return Finding(
            name="Platform Context",
            status="INFO",
            severity="INFO",
            detail=f"{self.os_name} {self.os_release}",
            recommendation=(
                "Review operating-system patching and hardening through the "
                "platform's approved management process."
            ),
            csf_category="PR.PS - Platform Security",
        )

    def check_local_ports(self) -> Finding:
        """Check localhost for a small set of commonly sensitive service ports."""
        open_ports: list[str] = []

        for port, service in self.RISKY_LOCAL_PORTS.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(0.2)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    open_ports.append(f"{port}/{service}")
            except OSError:
                continue
            finally:
                sock.close()

        if open_ports:
            return Finding(
                name="Local Service Exposure",
                status="REVIEW",
                severity="MEDIUM",
                detail=(
                    "Listening services detected on reviewed ports: "
                    + ", ".join(open_ports)
                ),
                recommendation=(
                    "Confirm each listening service is required and appropriately "
                    "restricted by host or network firewall policy."
                ),
                csf_category="PR.PS - Platform Security",
            )

        return Finding(
            name="Local Service Exposure",
            status="PASS",
            severity="INFO",
            detail=(
                "No listening services were detected on the reviewed localhost ports."
            ),
            recommendation=(
                "Continue periodic service and firewall review. This check covers "
                "only a small predefined port list."
            ),
            csf_category="PR.PS - Platform Security",
        )

    def check_environment_variable_names(self) -> Finding:
        """Flag environment-variable names that suggest secrets without exposing values."""
        matches = sorted(
            name
            for name in os.environ
            if any(hint in name.lower() for hint in self.SECRET_NAME_HINTS)
        )

        if matches:
            shown = ", ".join(matches[:5])
            suffix = f" (+{len(matches) - 5} more)" if len(matches) > 5 else ""
            return Finding(
                name="Environment Variable Secret Indicators",
                status="REVIEW",
                severity="MEDIUM",
                detail=(
                    f"Variable names that may contain secrets: {shown}{suffix}. "
                    "Values were not collected."
                ),
                recommendation=(
                    "Confirm sensitive values are managed according to the "
                    "environment's secrets-management policy and are not exposed "
                    "in logs or source control."
                ),
                csf_category="PR.DS - Data Security",
            )

        return Finding(
            name="Environment Variable Secret Indicators",
            status="PASS",
            severity="INFO",
            detail=(
                "No environment-variable names matched the configured "
                "secret-name indicators."
            ),
            recommendation=(
                "Continue using approved secrets-management practices. A name-based "
                "check cannot verify how secrets are actually stored."
            ),
            csf_category="PR.DS - Data Security",
        )

    def check_python_runtime(self) -> Finding:
        """Compare the running interpreter to the project's stated minimum version."""
        current = (sys.version_info.major, sys.version_info.minor)
        version = platform.python_version()
        minimum = ".".join(map(str, self.MINIMUM_PYTHON))

        if current >= self.MINIMUM_PYTHON:
            return Finding(
                name="Python Runtime Baseline",
                status="PASS",
                severity="INFO",
                detail=(
                    f"Running Python {version}; project minimum is Python {minimum}."
                ),
                recommendation=(
                    "Keep the interpreter patched and follow the Python project's "
                    "published support lifecycle."
                ),
                csf_category="PR.PS - Platform Security",
            )

        return Finding(
            name="Python Runtime Baseline",
            status="REVIEW",
            severity="MEDIUM",
            detail=f"Running Python {version}; project minimum is Python {minimum}.",
            recommendation=f"Upgrade to Python {minimum} or later before relying on this tool.",
            csf_category="PR.PS - Platform Security",
        )

    def check_temp_sensitive_files(self, max_files: int = 500) -> Finding:
        """Look for high-signal sensitive file extensions in shallow temporary paths."""
        matches: list[str] = []
        files_seen = 0

        for temp_dir in self.temp_dirs:
            if not temp_dir.exists() or not temp_dir.is_dir():
                continue

            try:
                for root, dirs, files in os.walk(temp_dir):
                    root_path = Path(root)
                    try:
                        depth = len(root_path.relative_to(temp_dir).parts)
                    except ValueError:
                        continue

                    if depth >= 2:
                        dirs[:] = []

                    for filename in files:
                        if files_seen >= max_files:
                            break
                        files_seen += 1
                        if (
                            Path(filename).suffix.lower()
                            in self.HIGH_SIGNAL_TEMP_EXTENSIONS
                        ):
                            matches.append(str(root_path / filename))

                    if files_seen >= max_files:
                        break
            except (PermissionError, OSError):
                continue

            if files_seen >= max_files:
                break

        if matches:
            redacted = [Path(item).name for item in matches[:5]]
            suffix = f" (+{len(matches) - 5} more)" if len(matches) > 5 else ""
            return Finding(
                name="Temporary File Review",
                status="REVIEW",
                severity="MEDIUM",
                detail=(
                    "Potentially sensitive file types found in temporary storage: "
                    f"{', '.join(redacted)}{suffix}."
                ),
                recommendation=(
                    "Confirm the files are necessary, protected, and removed from "
                    "temporary storage when no longer needed."
                ),
                csf_category="PR.DS - Data Security",
            )

        return Finding(
            name="Temporary File Review",
            status="PASS",
            severity="INFO",
            detail=(
                "No configured high-signal sensitive file types were found in the "
                f"first {files_seen} temporary files reviewed."
            ),
            recommendation=(
                "Continue protecting temporary storage. This check is intentionally "
                "shallow and does not inspect file contents."
            ),
            csf_category="PR.DS - Data Security",
        )

    def run_all_checks(self) -> list[Finding]:
        """Run all checks and retain their findings."""
        self.findings = [
            self.check_platform_context(),
            self.check_local_ports(),
            self.check_environment_variable_names(),
            self.check_python_runtime(),
            self.check_temp_sensitive_files(),
        ]
        return self.findings

    def overall_status(self) -> str:
        statuses = {finding.status for finding in self.findings}
        if "ERROR" in statuses:
            return "ERROR"
        if "REVIEW" in statuses:
            return "REVIEW_REQUIRED"
        return "NO_REVIEW_FINDINGS"

    def report_dict(self) -> dict[str, object]:
        counts = {
            status: sum(
                1 for finding in self.findings if finding.status == status
            )
            for status in ("PASS", "REVIEW", "INFO", "ERROR")
        }

        return {
            "audit_metadata": {
                "auditor": self.auditor_name,
                "hostname": self.hostname,
                "local_ip": self.local_ip,
                "operating_system": f"{self.os_name} {self.os_release}",
                "audit_time_utc": self.audit_time,
                "python_version": platform.python_version(),
            },
            "summary": {
                "overall_status": self.overall_status(),
                "counts": counts,
                "scope_note": (
                    "Read-only baseline checks; results require analyst review "
                    "and are not a compliance certification."
                ),
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def generate_json(self) -> str:
        return json.dumps(self.report_dict(), indent=2)

    def generate_text(self) -> str:
        report = self.report_dict()
        summary = report["summary"]
        lines = [
            "SECURITY AUDIT TOOL",
            "=" * 72,
            f"Host: {self.hostname}",
            f"OS: {self.os_name} {self.os_release}",
            f"Python: {platform.python_version()}",
            f"Overall status: {summary['overall_status']}",
            "",
        ]

        for finding in self.findings:
            lines.extend(
                [
                    f"[{finding.status}] {finding.name}",
                    f"  Severity: {finding.severity}",
                    f"  Detail: {finding.detail}",
                    f"  Recommendation: {finding.recommendation}",
                    f"  CSF 2.0 context: {finding.csf_category}",
                    "",
                ]
            )

        return "\n".join(lines).rstrip() + "\n"

    def save_json(self, output_path: str | Path) -> Path:
        path = Path(output_path)
        path.write_text(self.generate_json(), encoding="utf-8")
        return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a small set of read-only local host-security checks."
    )
    parser.add_argument(
        "--auditor",
        default="Security Audit Tool",
        help="Name recorded in the report metadata.",
    )
    parser.add_argument(
        "--output",
        default="security_audit_report.json",
        help="JSON report path.",
    )
    parser.add_argument(
        "--text",
        action="store_true",
        help="Print a text report to the console.",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not write the JSON report to disk.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    audit = SecurityAudit(auditor_name=args.auditor)
    findings = audit.run_all_checks()

    for finding in findings:
        print(f"[{finding.status}] {finding.name}")

    if args.text:
        print("\n" + audit.generate_text(), end="")

    if not args.no_save:
        saved = audit.save_json(args.output)
        print(f"\nReport saved to: {saved}")

    print(f"Overall status: {audit.overall_status()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
