"""
CyberGuardian AI Phase 3 + Phase 4 - Engine Tests

Comprehensive tests for all new threat detection engines.
"""

import pytest
from backend.engines import (
    message_engine,
    url_engine,
    context_engine,
    threat_engine,
    evidence_engine,
    risk_engine,
    analyzer,
)


# ============================================================================
# MESSAGE ENGINE TESTS
# ============================================================================

class TestMessageEngine:
    """Test message signal detection."""
    
    def test_urgency_detection(self):
        text = "Your account will be blocked immediately. Act now!"
        result = message_engine.analyze_message(text)
        assert result["signal_count"] > 0
        assert "URGENCY_MANIPULATION" in result["unique_categories"]
    
    def test_credential_request_detection(self):
        text = "Please verify your OTP: 123456"
        result = message_engine.analyze_message(text)
        assert "CREDENTIAL_REQUEST" in result["unique_categories"]
    
    def test_financial_request_detection(self):
        text = "Send UPI payment of Rs 500 processing fee"
        result = message_engine.analyze_message(text)
        assert "FINANCIAL_TARGETING" in result["unique_categories"]
    
    def test_no_signals_benign_message(self):
        text = "Hello, how are you today?"
        result = message_engine.analyze_message(text)
        assert result["signal_count"] == 0
        assert len(result["unique_categories"]) == 0
    
    def test_multiple_signals(self):
        text = "URGENT: Your bank account will be blocked. Send money immediately via UPI to verify."
        result = message_engine.analyze_message(text)
        assert result["signal_count"] >= 3
        assert "URGENCY_MANIPULATION" in result["unique_categories"]
        assert "FEAR_PRESSURE" in result["unique_categories"]
        assert "FINANCIAL_TARGETING" in result["unique_categories"]
    
    def test_authority_impersonation(self):
        text = "SBI Bank Security: Verify your password here"
        result = message_engine.analyze_message(text)
        assert "IMPERSONATION_AUTHORITY" in result["unique_categories"]
    
    def test_job_scam_detection(self):
        text = "Selected for job. Pay Rs 2000 registration fee. Earn Rs 50000/day work from home."
        result = message_engine.analyze_message(text)
        assert "JOB_SCAM" in result["unique_categories"]
    
    def test_claimed_brand_extraction(self):
        text = "Your SBI account is under threat"
        brand = message_engine.extract_claimed_brand(text)
        assert brand.lower() == "sbi"
    
    def test_action_extraction(self):
        text = "Click here to verify your account"
        action = message_engine.extract_action_requested(text)
        assert "click" in action.lower() or "verify" in action.lower()


# ============================================================================
# URL ENGINE TESTS
# ============================================================================

class TestURLEngine:
    """Test URL analysis."""
    
    def test_https_vs_http(self):
        https_url = "https://secure-site.com"
        http_url = "http://unsecured-site.com"
        
        https_result = url_engine.analyze_url(https_url)
        http_result = url_engine.analyze_url(http_url)
        
        assert https_result["features"]["uses_https"] is True
        assert http_result["features"]["uses_https"] is False
    
    def test_ip_address_detection(self):
        text_with_url = "Visit 192.168.1.1 now"
        urls = url_engine.find_urls(text_with_url)
        if urls:
            result = url_engine.analyze_url(urls[0])
            assert result["features"]["is_ip_address"] is True
    
    def test_url_shortener_detection(self):
        short_url = "https://bit.ly/abc123"
        result = url_engine.analyze_url(short_url)
        assert result["features"]["is_shortener"] is True
        assert result["risk_contribution"] > 0
    
    def test_excessive_length_detection(self):
        long_url = "https://example.com/" + "a" * 100
        result = url_engine.analyze_url(long_url)
        assert result["features"]["url_length"] > 100
        assert result["risk_contribution"] > 0
    
    def test_at_symbol_detection(self):
        malicious_url = "https://real-bank.com@fake-bank.com"
        result = url_engine.analyze_url(malicious_url)
        assert result["features"]["has_at_symbol"] is True
        assert result["risk_contribution"] > 15
    
    def test_subdomain_count(self):
        many_subdomains = "https://a.b.c.d.example.com"
        result = url_engine.analyze_url(many_subdomains)
        assert result["features"]["subdomain_count"] >= 3
    
    def test_brand_domain_mismatch(self):
        claimed_brand = "SBI"
        suspicious_url = "https://sbi-verify-account.com"
        result = url_engine.analyze_url(suspicious_url, claimed_brand)
        assert result["brand_context"].get("mismatch_detected") is True
        assert result["risk_contribution"] > 20
    
    def test_url_extraction_from_text(self):
        text = "Click here: https://example.com and also http://another-site.com"
        urls = url_engine.find_urls(text)
        assert len(urls) == 2
        assert "example.com" in urls[0]
        assert "another-site.com" in urls[1]
    
    def test_no_urls_in_text(self):
        text = "This is just regular text with no URLs"
        urls = url_engine.find_urls(text)
        assert len(urls) == 0


# ============================================================================
# CONTEXT ENGINE TESTS
# ============================================================================

class TestContextEngine:
    """Test context analysis."""
    
    def test_messaging_app_detection(self):
        context = context_engine.analyze_context(source_app="WhatsApp")
        assert context["app_category"] == "MESSAGING"
    
    def test_email_app_detection(self):
        context = context_engine.analyze_context(source_app="Gmail")
        assert context["app_category"] == "EMAIL"
    
    def test_impersonation_risk_high(self):
        context = context_engine.analyze_context(
            source_app="WhatsApp",
            claimed_brand="Amazon",
        )
        assert context["impersonation_risk"] is True
    
    def test_impersonation_risk_low(self):
        context = context_engine.analyze_context(
            source_app="Gmail",
            claimed_brand="RandomCompany",
        )
        assert context["impersonation_risk"] is False
    
    def test_suspicious_sender_name(self):
        context = context_engine.analyze_context(
            source_app="WhatsApp",
            sender="support",
        )
        assert len(context["signals"]) > 0


# ============================================================================
# THREAT ENGINE TESTS
# ============================================================================

class TestThreatEngine:
    """Test threat classification."""
    
    def test_phishing_classification(self):
        message = message_engine.analyze_message(
            "Verify your password at https://bank-secure.com"
        )
        url_result = url_engine.analyze_urls(
            ["https://bank-secure.com"],
            claimed_brand="SBI"
        )
        
        threat_type, _ = threat_engine.detect_threat(
            message_signals=message,
            url_analysis=url_result,
            context={},
            qr_found=False,
        )
        # Could be phishing or impersonation
        assert threat_type in ["PHISHING", "IMPERSONATION", "CREDENTIAL_THEFT"]
    
    def test_financial_scam_classification(self):
        message = message_engine.analyze_message(
            "Congratulations! You won Rs 100000. Send processing fee to claim."
        )
        
        threat_type, _ = threat_engine.detect_threat(
            message_signals=message,
            url_analysis={"analyzed": [], "all_signals": []},
            context={},
            qr_found=False,
        )
        assert threat_type == "FINANCIAL_SCAM"
    
    def test_safe_classification(self):
        message = message_engine.analyze_message(
            "Hi, how are you doing today?"
        )
        
        threat_type, _ = threat_engine.detect_threat(
            message_signals=message,
            url_analysis={"analyzed": [], "all_signals": []},
            context={},
            qr_found=False,
        )
        assert threat_type == "SAFE"
    
    def test_threat_recommendations(self):
        recs = threat_engine.get_threat_recommendations("PHISHING")
        assert len(recs) > 0
        assert any("do not click" in r.lower() for r in recs)


# ============================================================================
# EVIDENCE ENGINE TESTS
# ============================================================================

class TestEvidenceEngine:
    """Test evidence collection and structuring."""
    
    def test_message_evidence_collection(self):
        signals = [
            {
                "category": "URGENCY_MANIPULATION",
                "indicator": "Immediate action requested",
                "severity": "MEDIUM",
                "matched_text": "immediately",
                "base_score": 12,
                "evidence": "Detected phrase: 'immediately'",
            }
        ]
        
        evidence_list = evidence_engine.collect_message_evidence(signals, "test")
        assert len(evidence_list) == 1
        assert evidence_list[0].category == "URGENCY_MANIPULATION"
    
    def test_evidence_aggregation(self):
        message_evidence = [
            evidence_engine.Evidence(
                evidence_id="test_1",
                category="URGENCY_MANIPULATION",
                indicator="Test",
                severity="HIGH",
                title="Test",
                description="Test",
                source="MESSAGE",
                matched_value="test",
                score_contribution=10,
            )
        ]
        
        result = evidence_engine.aggregate_evidence(
            message_evidence=message_evidence,
            url_evidence=[],
            context_evidence=[],
        )
        
        assert result["total_evidence_items"] == 1
        assert len(result["all_evidence"]) == 1


# ============================================================================
# RISK ENGINE TESTS
# ============================================================================

class TestRiskEngine:
    """Test risk scoring."""
    
    def test_score_bounds(self):
        # Score must always be 0-100
        evidence = [
            {
                "indicator": "Test",
                "score_contribution": 1000,  # Huge score
                "severity": "CRITICAL",
                "matched_value": "test",
            }
        ]
        
        result = risk_engine.calculate_risk(
            message_evidence=evidence,
            url_evidence=[],
            context_evidence=[],
            qr_found=False,
        )
        
        assert 0 <= result["score"] <= 100
    
    def test_safe_message_low_risk(self):
        result = risk_engine.calculate_risk(
            message_evidence=[],
            url_evidence=[],
            context_evidence=[],
            qr_found=False,
        )
        
        assert result["score"] == 0
        assert result["level"] == "SAFE"
    
    def test_high_risk_classification(self):
        # A single message-only evidence item is capped at
        # risk_engine.MAX_SIGNAL_CONTRIBUTION (65) by design, so it can
        # reach HIGH but not CRITICAL on its own — URL/context evidence
        # (its own separate budget) is required to push higher. This
        # cap is intentional: it prevents one inflated score_contribution
        # from a single source from dominating the whole score.
        evidence = [
            {
                "indicator": "Critical threat",
                "score_contribution": 85,
                "severity": "CRITICAL",
                "matched_value": "critical",
            }
        ]
        
        result = risk_engine.calculate_risk(
            message_evidence=evidence,
            url_evidence=[],
            context_evidence=[],
            qr_found=False,
        )
        
        assert result["score"] == risk_engine.MAX_SIGNAL_CONTRIBUTION
        assert result["level"] == "HIGH"


# ============================================================================
# ANALYZER ORCHESTRATOR TESTS
# ============================================================================

class TestAnalyzerOrchestrator:
    """Test unified analysis pipeline."""
    
    def test_phishing_scenario(self):
        text = (
            "URGENT: Your Amazon account will be suspended. "
            "Verify immediately at https://verify-amazon-secure.com"
        )
        
        result = analyzer.analyze_notification(
            text=text,
            source_app="Gmail",
            sender="Amazon",
        )
        
        assert result["success"] is True
        assert result["threat"]["primary"] in [
            "PHISHING", "IMPERSONATION", "CREDENTIAL_THEFT"
        ]
        assert result["risk"]["score"] > 50
    
    def test_financial_scam_scenario(self):
        text = (
            "Congratulations! You won Rs 1 Lakh. "
            "Send Rs 500 registration fee via UPI."
        )
        
        result = analyzer.analyze_notification(
            text=text,
            source_app="WhatsApp",
            sender="Winner Notification",
        )
        
        assert result["threat"]["primary"] in ["FINANCIAL_SCAM", "SUSPICIOUS"]
        assert result["risk"]["score"] > 40
    
    def test_benign_scenario(self):
        text = "Hi! How are you doing today?"
        
        result = analyzer.analyze_notification(
            text=text,
            source_app="WhatsApp",
            sender="Friend",
        )
        
        assert result["threat"]["primary"] == "SAFE"
        assert result["risk"]["score"] < 25
    
    def test_full_analysis_structure(self):
        text = "Click here: https://example.com"
        
        result = analyzer.analyze_notification(text=text)
        
        # Check all required fields
        assert "success" in result
        assert "threat" in result
        assert "risk" in result
        assert "message_analysis" in result
        assert "url_analysis" in result
        assert "evidence" in result
        assert "recommendations" in result
        assert result["risk"]["score"] >= 0 and result["risk"]["score"] <= 100


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    """Test complete workflows."""
    
    def test_phishing_attack_full_flow(self):
        """Test complete phishing attack analysis."""
        text = (
            "Your SBI Bank account is compromised. "
            "Your balance: Rs 500000 is at risk. "
            "Click here to verify: https://sbi-verify-account.com/secure"
        )
        
        result = analyzer.analyze_notification(
            text=text,
            source_app="SMS",
            sender="SBI",
        )
        
        # Should identify as high/critical threat
        assert result["risk"]["score"] >= 70
        # FINANCIAL_SCAM is the primary category the Phase 3/4 spec's
        # own worked example (Section 42) expects for this exact shape
        # of message (account-risk + verify link + brand/domain
        # mismatch); IMPERSONATION/PHISHING/CREDENTIAL_THEFT are the
        # other threat types this scenario's signals can defensibly
        # resolve to depending on exact wording.
        assert result["threat"]["primary"] in [
            "PHISHING", "CREDENTIAL_THEFT", "IMPERSONATION", "FINANCIAL_SCAM"
        ]
        
        # Should have evidence
        assert result["evidence"]["total_items"] > 0
        
        # Should have recommendations
        assert len(result["recommendations"]) > 0
    
    def test_job_scam_full_flow(self):
        """Test complete job scam analysis."""
        text = (
            "Selected for high-paying work from home job! "
            "Rs 50000 salary guarantee. "
            "Send Rs 1000 registration fee to confirm."
        )
        
        result = analyzer.analyze_notification(text=text)
        
        assert result["threat"]["primary"] in ["JOB_SCAM", "FINANCIAL_SCAM"]
        assert result["risk"]["score"] > 50


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
