from django.urls import path, re_path
from .views import HealthCheckViewSet

urlpatterns = [
    re_path(r'^health-check$', HealthCheckViewSet.as_view({'get': 'get_status'}))
]