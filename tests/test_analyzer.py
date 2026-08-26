"""
CyberGuardian AI - Unit tests

Run with:
    python -m pytest tests/
or simply:
    python -m unittest discover tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import analyzer, url_analyzer, risk_engine
from config import Config


class TestUrlAnalyzer(unittest.TestCase):
    def test_finds_urls_in_text(self):
        text = "Verify now: https://example.com/verify or visit www.test.com"
        urls = url_analyzer.find_urls(text)
        self.assertEqual(len(urls), 2)

    def test_ip_based_url_flagged(self):
        result = url_analyzer.analyze_url("http://192.168.1.5/login")
        self.assertIn("Uses a raw IP address instead of a domain name", result["indicators"])
        self.assertGreater(result["risk_contribution"], 0)

    def test_safe_url_low_risk(self):
        result = url_analyzer.analyze_url("https://www.wikipedia.org/wiki/Cybersecurity")
        self.assertLess(result["risk_contribution"], 20)

    def test_at_symbol_flagged(self):
        result = url_analyzer.analyze_url("http://real-bank.com@fake-site.example.com/login")
        self.assertIn("Contains '@' symbol, which can mask the real destination", result["indicators"])


class TestTextAnalyzer(unittest.TestCase):
    def test_detects_urgency_and_credential_request(self):
        text = "Your account will be blocked immediately. Verify your password now."
        result = analyzer.analyze_text(text)
        self.assertIn("URGENCY", result["signals"])
        self.assertIn("FEAR", result["signals"])
        self.assertIn("CREDENTIAL_REQUEST", result["signals"])

    def test_safe_text_has_no_signals(self):
        text = "Hey, are we still meeting for lunch tomorrow at 1pm?"
        result = analyzer.analyze_text(text)
        self.assertEqual(result["signal_count"], 0)

    def test_job_scam_hint(self):
        text = "You have been selected for a work from home job. Pay a registration fee to confirm."
        result = analyzer.analyze_text(text)
        self.assertTrue(result["job_scam_hint"])


class TestRiskEngine(unittest.TestCase):
    def test_safe_content_scores_low(self):
        signals = {}
        url_analysis = {"analyzed": [], "max_risk_contribution": 0, "all_indicators": []}
        risk = risk_engine.calculate_risk(signals, url_analysis, qr_found=False, bands=Config.RISK_BANDS)
        self.assertEqual(risk["score"], 0)
        self.assertEqual(risk["level"], "LOW")

    def test_high_risk_combination_scores_high(self):
        text = "Your account will be blocked immediately. Verify your password and OTP now: http://192.168.1.5/login/verify"
        text_signals = analyzer.analyze_text(text)
        urls = url_analyzer.find_urls(text)
        url_analysis = url_analyzer.analyze_urls(urls)
        risk = risk_engine.calculate_risk(
            text_signals["signals"], url_analysis, qr_found=False, bands=Config.RISK_BANDS
        )
        self.assertGreaterEqual(risk["score"], 60)
        self.assertIn(risk["level"], ["HIGH", "CRITICAL"])

    def test_result_depends_on_input_not_hardcoded(self):
        """Two different inputs must not produce the same score - guards
        against a hardcoded/fake result."""
        text_a = "Hey, lunch tomorrow?"
        text_b = "URGENT: verify your password immediately or your account will be suspended: http://192.168.0.1/login"

        def score_for(text):
            signals = analyzer.analyze_text(text)
            urls = url_analyzer.analyze_urls(url_analyzer.find_urls(text))
            return risk_engine.calculate_risk(signals["signals"], urls, False, Config.RISK_BANDS)["score"]

        self.assertNotEqual(score_for(text_a), score_for(text_b))


class TestThreatClassification(unittest.TestCase):
    def test_classifies_phishing(self):
        text = "Bank alert: verify your password immediately to avoid suspension: http://192.168.1.5/login/verify"
        signals = analyzer.analyze_text(text)
        urls = url_analyzer.analyze_urls(url_analyzer.find_urls(text))
        threat = analyzer.classify_threat(
            signals["signals"], urls["max_risk_contribution"], qr_found=False,
            job_scam_hint=signals["job_scam_hint"]
        )
        self.assertEqual(threat, "PHISHING")

    def test_classifies_safe(self):
        text = "See you at 6pm!"
        signals = analyzer.analyze_text(text)
        urls = url_analyzer.analyze_urls(url_analyzer.find_urls(text))
        threat = analyzer.classify_threat(
            signals["signals"], urls["max_risk_contribution"], qr_found=False,
            job_scam_hint=signals["job_scam_hint"]
        )
        self.assertEqual(threat, "SAFE")


if __name__ == "__main__":
    unittest.main()
