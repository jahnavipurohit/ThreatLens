from django.urls import path
from . import views

urlpatterns = [
    path("analyze-email", views.analyze_email),
    path("analysis/<uuid:analysis_id>", views.analysis_detail),
    path("analysis/<uuid:analysis_id>/report", views.report),
    path("intel/ip/<str:ip>", views.ip_intelligence),
]
