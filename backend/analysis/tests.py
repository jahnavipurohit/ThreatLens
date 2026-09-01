from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from unittest.mock import patch
from analysis.services.parser import parse_email
from analysis.services.threat import analyze

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
