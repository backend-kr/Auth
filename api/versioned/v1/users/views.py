import logging

from django.contrib.auth import get_user_model, logout
from rest_framework import viewsets, filters
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import Serializer
from rest_framework.status import HTTP_200_OK

from api.versioned.v1.users.serializers import UserSerializer, UserCreateSerializer
from common.permissions import IsOwner
from axes.utils import reset as axes_reset


logger = logging.getLogger('django.server')



class UserViewSet(viewsets.ModelViewSet):
    queryset = get_user_model().objects.all().prefetch_related('groups', 'user_permissions')
    serializer_class = UserSerializer
    filter_backends = (filters.SearchFilter,)
    search_fields = ('^email',)
    serializer_action_map = {
        'create': UserCreateSerializer,
        'health_check': Serializer,
        'logout': Serializer
    }
    permission_classes = [IsOwner]
    permission_classes_map = {
        'health_check': [AllowAny],
        'create': [AllowAny],
    }

    def get_permissions(self):
        permission_classes = self.permission_classes
        if self.permission_classes_map.get(self.action, None):
            permission_classes = self.permission_classes_map[self.action]

        return [permission() for permission in permission_classes]

    def get_serializer_class(self):
        if self.serializer_action_map.get(self.action, None):
            return self.serializer_action_map[self.action]
        return self.serializer_class

    def logout(self, request, *args, **kwargs):
        logout(request)
        return Response(status=HTTP_200_OK)

    def health_check(self, request, *args, **kwargs):
        return Response(status=HTTP_200_OK)

    def perform_create(self, serializer):
        serializer.save()
        axes_reset(username=serializer.data.get('email'))
