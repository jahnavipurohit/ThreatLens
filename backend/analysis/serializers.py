from rest_framework import serializers
from .models import EmailAnalysis

class EmailAnalysisSerializer(serializers.ModelSerializer):
    analysis_id = serializers.UUIDField(source="id", read_only=True)
    class Meta:
        model = EmailAnalysis
        fields = ["analysis_id", "created_at", "file_name", "file_hash", "subject", "sender", "verdict", "threat_score", "origin_confidence", "result"]

