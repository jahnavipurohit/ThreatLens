from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from unittest.mock import MagicMock, patch
from analysis.services.parser import parse_email
from analysis.services.threat import analyze
from analysis.services.ip_intelligence import enrich_ip, enrich_origin
from analysis.services.risk_engine import calculate_final_assessment

SAMPLE = b"""From: Finance Team <billing@trusted.example>
Reply-To: attacker@lookalike.example
To: user@example.com
Subject: Urgent: verify your account
Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail
Received: from mail.bad.example (mail.bad.example [203.0.113.18]) by mx.example; Mon, 31 Aug 2026 10:00:00 +0530
Content-Type: text/plain; charset=utf-8

Act now. Click here to verify your password: https://lookalike.example/login
"""

class AnalysisApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_rejects_non_eml(self):
        response = self.client.post("/api/analyze-email", {"file": SimpleUploadedFile("note.txt", b"hello")}, format="multipart")
        self.assertEqual(response.status_code, 400)

    def test_analyzes_and_persists_eml(self):
        response = self.client.post("/api/analyze-email", {"file": SimpleUploadedFile("threat.eml", SAMPLE, content_type="message/rfc822")}, format="multipart")
        self.assertEqual(response.status_code, 201)
        self.assertGreaterEqual(response.data["threat_score"], 50)
        self.assertEqual(response.data["result"]["assessment"]["authentication"]["spf"], "fail")
        self.assertIn("huggingface_model", response.data["result"]["assessment"])
        self.assertIn("fraud_confidence", response.data["result"]["assessment"])
        self.assertEqual(response.data["result"]["final_assessment"]["verdict"], "unsafe")
        detail = self.client.get(f'/api/analysis/{response.data["analysis_id"]}')
        self.assertEqual(detail.status_code, 200)

    @patch("analysis.services.threat.predict_huggingface")
    @patch("analysis.services.threat.predict")
    def test_parallel_model_confidence_blend(self, existing_predict, roberta_predict):
        existing_predict.return_value = {"phishing_probability": 0.5, "engine": "existing"}
        roberta_predict.return_value = {
            "available": True,
            "fraud_probability": 0.9,
            "label": "fraud",
            "engine": "roberta",
            "error": None,
        }
        assessment = analyze(parse_email(SAMPLE))
        self.assertEqual(assessment["fraud_confidence"], 0.74)
        self.assertIn("40%", assessment["confidence_method"])

    @patch("analysis.services.ip_intelligence.urlopen")
    def test_origin_ip_enrichment(self, mocked_urlopen):
        response = MagicMock()
        response.read.return_value = b'{"success":true,"country":"United States","country_code":"US","region":"California","city":"Mountain View","latitude":37.4,"longitude":-122.1,"connection":{"asn":15169,"org":"Google LLC","isp":"Google","type":"Corporate"},"security":{"proxy":false,"vpn":false,"tor":false,"hosting":true}}'
        mocked_urlopen.return_value.__enter__.return_value = response
        enrich_ip.cache_clear()
        parsed = {"received": [{"index": 1, "trust": "unverified", "ips": [{"value": "8.8.8.8", "classification": "public"}]}]}
        result = enrich_origin(parsed)
        self.assertTrue(result["available"])
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["location"]["city"], "Mountain View")
        self.assertEqual(result["network"]["type"], "Hosting / data center")
        self.assertEqual(result["confidence"], "infrastructure only")

    def test_private_ip_is_not_geolocated(self):
        enrich_ip.cache_clear()
        result = enrich_ip("192.168.1.20")
        self.assertFalse(result["available"])
        self.assertIn("Private or reserved", result["error"])

    def test_final_assessment_thresholds(self):
        safe = calculate_final_assessment({"score": 10, "fraud_confidence": 0.1}, {"security": {}})
        unsafe = calculate_final_assessment({"score": 90, "fraud_confidence": 0.9}, {"security": {"tor": True}})
        self.assertEqual(safe["verdict"], "safe")
        self.assertEqual(unsafe["verdict"], "unsafe")
        self.assertEqual(unsafe["score"], 91)
