from django.urls import path, re_path

from api.versioned.v1.users.views import UserViewSet, UserLoginTokenViewSet


urlpatterns = [
    re_path('^$', UserViewSet.as_view({'post': 'create'})),
    re_path(r'^login$', UserLoginTokenViewSet.as_view({'post': 'create'})),
    re_path(r'^_health_check$', UserViewSet.as_view({'get': 'health_check'})),
]