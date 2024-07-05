import logging

from django.conf import settings
from django.contrib.auth import get_user_model, logout, user_logged_in
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from rest_framework import viewsets, filters
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import Serializer
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST

from .serializers import UserSerializer, UserCreateSerializer, UserLoginSerializer
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


class UserLoginTokenViewSet(viewsets.GenericViewSet):
    """
    create:[로그인]
    일정 횟수(**기본:5회**)만큼 연속 로그인 실패시 계정이 잠깁니다.<br>
    잠긴 계정은 일정 시간(**기본:30분**) 기준으로 잠김 해제됩니다.<br>
    토큰의 만료 시점은 서버에서 관리되며, 토큰 만료시 권한이 필요한 API를 호출하는 경우 status 403이 전달됩니다.<br>
    중복 로그인 허용됩니다.<br>
    force_login 사용시 기존 발급 토큰은 삭제됩니다. (중복 로그인 방지 효과)<br>

    **로그인 실패시(401)에 대한 코드 정의**
    * authentication_failed : 아이디/비밀번호 오류
    * not_authenticated : 비활성화 유저
    """
    permission_classes = [AllowAny]
    serializer_class = UserLoginSerializer

    def dispatch(self, request, *args, **kwargs):
        self._request = request
        return super(UserLoginTokenViewSet, self).dispatch(request, *args, **kwargs)

    @method_decorator(never_cache)
    def create(self, request, *args, **kwargs):
        encrypt = 'encrypted' in request.query_params

        # if encrypt:
        #     _key = getattr(settings, 'ENCRYPT_KEY', str(Fernet.generate_key()))
        #     _f = Fernet(_key.encode())
        #     try:
        #         request.data.update({'password': _f.decrypt(request.data.get('password').encode()).decode('utf-8')})
        #     except InvalidToken:
        #         raise ParseError('Token parse error')

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.data.get('user')
            axes_reset(username=user.get('email'))

            data = serializer.data

            _user = get_user_model().objects.get(is_active=True, email=user.get('email'))

            user_logged_in.send(sender=_user.__class__, request=request, user=_user)

            return Response(data)
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)
