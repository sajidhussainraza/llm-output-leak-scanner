"""Tests for leak_scanner.py. Run: python -m unittest discover tests -v"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from leak_scanner import redact, scan, summarize  # noqa: E402


class TestScanner(unittest.TestCase):
    def test_clean_text(self):
        self.assertEqual(scan("Hello, this is a normal summary."), [])

    def test_email_and_phone(self):
        kinds = {f["type"] for f in scan(
            "Contact me at jane@example.com or 0300-1234567.")}
        self.assertIn("email", kinds)
        self.assertIn("phone", kinds)

    def test_aws_key_and_jwt(self):
        text = ("Key AKIAIOSFODNN7EXAMPLE and token "
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature")
        kinds = {f["type"] for f in scan(text)}
        self.assertIn("aws_access_key", kinds)
        self.assertIn("jwt", kinds)

    def test_credit_card_needs_luhn(self):
        # 4111 1111 1111 1111 is Luhn-valid; 1234 5678 9012 3456 is not.
        self.assertTrue(any(f["type"] == "credit_card"
                            for f in scan("Card 4111 1111 1111 1111")))
        self.assertFalse(any(f["type"] == "credit_card"
                             for f in scan("Code 1234 5678 9012 3456")))

    def test_password_assignment(self):
        self.assertTrue(any(f["type"] == "password"
                            for f in scan("password: hunter2secret")))

    def test_redact_removes_secrets(self):
        out = redact("Reach jane@example.com, key AKIAIOSFODNN7EXAMPLE")
        self.assertNotIn("jane@example.com", out)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        self.assertIn("[REDACTED:email]", out)

    def test_summarize_worst(self):
        worst, counts = summarize(scan("jane@example.com\n"
                                        "-----BEGIN PRIVATE KEY-----"))
        self.assertEqual(worst, "critical")
        self.assertEqual(counts["email"], 1)


if __name__ == "__main__":
    unittest.main()
