import hashlib
from concurrent.futures import ThreadPoolExecutor
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
from .services.ip_intelligence import enrich_ip, enrich_origin
from .services.risk_engine import calculate_final_assessment

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
        with ThreadPoolExecutor(max_workers=2) as executor:
            assessment_future = executor.submit(analyze, parsed)
            origin_future = executor.submit(enrich_origin, parsed)
            assessment = assessment_future.result()
            origin_intelligence = origin_future.result()
    except Exception as exc:
        return Response({"error": f"Unable to parse email: {exc}"}, status=status.HTTP_400_BAD_REQUEST)
    final_assessment = calculate_final_assessment(assessment, origin_intelligence)
    result = {**parsed, "assessment": assessment, "origin_intelligence": origin_intelligence, "final_assessment": final_assessment, "caveat": "Origin information represents observable infrastructure, not a person's physical location."}
    record = EmailAnalysis.objects.create(file_name=upload.name, file_hash=hashlib.sha256(raw).hexdigest(), subject=parsed["metadata"]["subject"], sender=parsed["metadata"]["from"], verdict=final_assessment["verdict"], threat_score=final_assessment["score"], origin_confidence=assessment["origin_confidence"], result=result)
    return Response(EmailAnalysisSerializer(record).data, status=status.HTTP_201_CREATED)

@api_view(["GET"])
def analysis_detail(request, analysis_id):
    return Response(EmailAnalysisSerializer(get_object_or_404(EmailAnalysis, id=analysis_id)).data)

@api_view(["GET"])
def ip_intelligence(request, ip):
    result = enrich_ip(ip)
    return Response(result, status=status.HTTP_200_OK if result.get("available") else status.HTTP_422_UNPROCESSABLE_ENTITY)

@api_view(["GET"])
def report(request, analysis_id):
    item = get_object_or_404(EmailAnalysis, id=analysis_id)
    final = item.result.get("final_assessment", {})
    lines = ["EMAIL THREAT FORENSIC REPORT", f"Analysis ID: {item.id}", f"File: {item.file_name}", f"SHA-256: {item.file_hash}", f"Subject: {item.subject}", f"Sender: {item.sender}", f"Final verdict: {final.get('label', item.verdict)} ({item.threat_score}/100)", final.get("explanation", ""), f"Origin confidence: {item.origin_confidence}/100", "", "Evidence:"]
    lines.extend(f'- {e["description"]} (+{e["weight"]})' for e in item.result.get("assessment", {}).get("evidence", []))
    origin = item.result.get("origin_intelligence", {})
    if origin.get("ip"):
        location = origin.get("location", {})
        network = origin.get("network", {})
        lines.extend(["", "Origin infrastructure:", f"- IP: {origin['ip']}", f"- Location: {location.get('city') or 'Unknown'}, {location.get('region') or 'Unknown'}, {location.get('country') or 'Unknown'}", f"- ASN/Organization: {network.get('asn') or 'Unknown'} / {network.get('organization') or network.get('isp') or 'Unknown'}", f"- Network type: {network.get('type') or 'Unknown'}"])
    lines.extend(["", item.result.get("caveat", "")])
    response = HttpResponse("\n".join(lines), content_type="text/plain")
    response["Content-Disposition"] = f'attachment; filename="forensic-report-{item.id}.txt"'
    return response
