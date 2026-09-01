import hashlib
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from .models import EmailAnalysis
from .serializers import EmailAnalysisSerializer
from .services.parser import parse_email
from .services.threat import analyze

@api_view(["POST"])
@parser_classes([MultiPartParser])
def analyze_email(request):
    upload = request.FILES.get("file")
    if not upload or not upload.name.lower().endswith(".eml"):
        return Response({"error": "Upload a valid .eml file."}, status=status.HTTP_400_BAD_REQUEST)
    if upload.size > 10 * 1024 * 1024:
        return Response({"error": "File exceeds the 10 MB prototype limit."}, status=status.HTTP_400_BAD_REQUEST)
    raw = upload.read()
    try:
        parsed = parse_email(raw)
        assessment = analyze(parsed)
    except Exception as exc:
        return Response({"error": f"Unable to parse email: {exc}"}, status=status.HTTP_400_BAD_REQUEST)
    result = {**parsed, "assessment": assessment, "caveat": "Origin information represents observable infrastructure, not a person's physical location."}
    record = EmailAnalysis.objects.create(file_name=upload.name, file_hash=hashlib.sha256(raw).hexdigest(), subject=parsed["metadata"]["subject"], sender=parsed["metadata"]["from"], verdict=assessment["severity"], threat_score=assessment["score"], origin_confidence=assessment["origin_confidence"], result=result)
    return Response(EmailAnalysisSerializer(record).data, status=status.HTTP_201_CREATED)

@api_view(["GET"])
def analysis_detail(request, analysis_id):
    return Response(EmailAnalysisSerializer(get_object_or_404(EmailAnalysis, id=analysis_id)).data)

@api_view(["GET"])
def report(request, analysis_id):
    item = get_object_or_404(EmailAnalysis, id=analysis_id)
    lines = ["EMAIL THREAT FORENSIC REPORT", f"Analysis ID: {item.id}", f"File: {item.file_name}", f"SHA-256: {item.file_hash}", f"Subject: {item.subject}", f"Sender: {item.sender}", f"Threat: {item.verdict} ({item.threat_score}/100)", f"Origin confidence: {item.origin_confidence}/100", "", "Evidence:"]
    lines.extend(f'- {e["description"]} (+{e["weight"]})' for e in item.result.get("assessment", {}).get("evidence", []))
    lines.extend(["", item.result.get("caveat", "")])
    response = HttpResponse("\n".join(lines), content_type="text/plain")
    response["Content-Disposition"] = f'attachment; filename="forensic-report-{item.id}.txt"'
    return response

