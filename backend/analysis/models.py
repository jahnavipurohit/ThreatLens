import uuid
from django.db import models

class EmailAnalysis(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    file_name = models.CharField(max_length=255)
    file_hash = models.CharField(max_length=64, db_index=True)
    subject = models.TextField(blank=True)
    sender = models.CharField(max_length=320, blank=True)
    verdict = models.CharField(max_length=20, default="Unknown")
    threat_score = models.PositiveSmallIntegerField(default=0)
    origin_confidence = models.PositiveSmallIntegerField(default=0)
    result = models.JSONField(default=dict)

    class Meta:
        ordering = ["-created_at"]

