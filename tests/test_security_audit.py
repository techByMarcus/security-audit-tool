import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from security_audit import Finding, SecurityAudit


class SecurityAuditTests(unittest.TestCase):
    def test_finding_serializes_to_dict(self):
        finding = Finding("Name", "PASS", "INFO", "detail", "recommend", "PR.PS")
        self.assertEqual(finding.to_dict()["status"], "PASS")

    @patch("security_audit.socket.gethostbyname", side_effect=OSError)
    def test_local_ip_falls_back_to_unknown(self, _mock_lookup):
        self.assertEqual(SecurityAudit._get_local_ip(), "UNKNOWN")

    @patch.dict(os.environ, {"EXAMPLE_API_KEY": "super-secret-value"}, clear=True)
    def test_environment_check_redacts_values(self):
        audit = SecurityAudit(temp_dirs=[])
        finding = audit.check_environment_variable_names()
        self.assertEqual(finding.status, "REVIEW")
        self.assertIn("EXAMPLE_API_KEY", finding.detail)
        self.assertNotIn("super-secret-value", finding.detail)

    @patch.dict(os.environ, {"PATH": "/usr/bin"}, clear=True)
    def test_environment_check_passes_without_secret_name(self):
        audit = SecurityAudit(temp_dirs=[])
        finding = audit.check_environment_variable_names()
        self.assertEqual(finding.status, "PASS")

    def test_temp_file_check_flags_high_signal_extension(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir, "client.pem").write_text("test", encoding="utf-8")
            audit = SecurityAudit(temp_dirs=[temp_dir])
            finding = audit.check_temp_sensitive_files()
            self.assertEqual(finding.status, "REVIEW")
            self.assertIn("client.pem", finding.detail)

    def test_temp_file_check_ignores_plain_text(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir, "notes.txt").write_text("test", encoding="utf-8")
            audit = SecurityAudit(temp_dirs=[temp_dir])
            finding = audit.check_temp_sensitive_files()
            self.assertEqual(finding.status, "PASS")

    @patch("security_audit.socket.socket")
    def test_local_ports_pass_when_reviewed_ports_closed(self, mock_socket):
        instance = Mock()
        instance.connect_ex.return_value = 1
        mock_socket.return_value = instance
        audit = SecurityAudit(temp_dirs=[])
        finding = audit.check_local_ports()
        self.assertEqual(finding.status, "PASS")
        self.assertTrue(instance.close.called)

    @patch("security_audit.socket.socket")
    def test_local_ports_flag_listening_service(self, mock_socket):
        instance = Mock()
        instance.connect_ex.side_effect = [1, 0, 1, 1, 1, 1, 1]
        mock_socket.return_value = instance
        audit = SecurityAudit(temp_dirs=[])
        finding = audit.check_local_ports()
        self.assertEqual(finding.status, "REVIEW")
        self.assertIn("23/Telnet", finding.detail)

    def test_report_json_is_valid_and_has_scope_note(self):
        audit = SecurityAudit(temp_dirs=[])
        audit.findings = [
            Finding("Context", "INFO", "INFO", "detail", "recommend", "PR.PS"),
            Finding("Check", "PASS", "INFO", "detail", "recommend", "PR.DS"),
        ]
        parsed = json.loads(audit.generate_json())
        self.assertEqual(parsed["summary"]["overall_status"], "NO_REVIEW_FINDINGS")
        self.assertIn(
            "not a compliance certification",
            parsed["summary"]["scope_note"],
        )

    def test_overall_status_requires_review_when_review_finding_exists(self):
        audit = SecurityAudit(temp_dirs=[])
        audit.findings = [
            Finding("Check", "REVIEW", "MEDIUM", "detail", "recommend", "PR.PS")
        ]
        self.assertEqual(audit.overall_status(), "REVIEW_REQUIRED")


if __name__ == "__main__":
    unittest.main()
