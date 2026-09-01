import uuid
from django.db import migrations, models

class Migration(migrations.Migration):
    initial = True
    dependencies = []
    operations = [
        migrations.CreateModel(
            name="EmailAnalysis",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("file_name", models.CharField(max_length=255)),
                ("file_hash", models.CharField(db_index=True, max_length=64)),
                ("subject", models.TextField(blank=True)),
                ("sender", models.CharField(blank=True, max_length=320)),
                ("verdict", models.CharField(default="Unknown", max_length=20)),
                ("threat_score", models.PositiveSmallIntegerField(default=0)),
                ("origin_confidence", models.PositiveSmallIntegerField(default=0)),
                ("result", models.JSONField(default=dict)),
            ],
            options={"ordering": ["-created_at"]},
        )
    ]

