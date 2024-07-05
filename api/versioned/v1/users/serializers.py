import logging
from importlib import import_module

from django.conf import settings
from django.contrib.auth import get_user_model, authenticate, password_validation as validators
from django.contrib.sites.models import Site
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError as django_validation_error

from rest_framework import serializers, status
from rest_framework.exceptions import ValidationError, NotAuthenticated, AuthenticationFailed

from api.bases.users.models import Profile, Image, User, ExpiringToken
from common.exceptions import ConflictException

logger = logging.getLogger('django.server')


def get_username_field():
    try:
        username_field = get_user_model().USERNAME_FIELD
    except:
        username_field = 'username'

    return username_field


class ImageSerializer(serializers.ModelSerializer):
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    width = serializers.IntegerField(read_only=True, help_text='이미지 넓이')
    height = serializers.IntegerField(read_only=True, help_text='이미지 높이')

    class Meta:
        model = Image
        fields = '__all__'

    def create(self, validated_data):
        model = self.Meta.model
        instance = model.objects.create(file=validated_data['file'])
        user = validated_data['user']
        try:
            user.profile.avatar = instance
            user.profile.save()
        except Exception as e:
            logger.error(e)

        return instance

class ProfileSerializer(serializers.ModelSerializer):
    config = serializers.JSONField(required=False)
    email = serializers.EmailField(source='user.email', read_only=True)
    is_contracted = serializers.BooleanField(read_only=True)
    gender = serializers.SerializerMethodField(read_only=True)
    avatar = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Profile
        fields = '__all__'
        extra_kwargs = {
            'user': {'read_only': True}
        }

    def get_fields(self):
        fields = super().get_fields()
        return fields

    def get_gender(self, obj):
        if obj.gender_code is not None:
            return "male" if obj.gender_code % 2 else "female"
        return obj.gender_code

    def get_avatar(self, instance):
        if hasattr(instance, 'avatar') and hasattr(instance.avatar, 'file'):
            return ImageSerializer(instance.avatar).data

        return Image.default_image(instance.user.get_random_digit())

def get_site(request):
    try:
        return get_current_site(request)
    except Site.DoesNotExist:
        raise ValidationError(detail='unregistered domain name from request.')


class UserCreateSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, required=False)
    profile = ProfileSerializer(required=False)

    class Meta:
        model = get_user_model()
        fields = ('email', 'password', 'id', 'profile')

    def validate(self, attrs):
        password = attrs.get('password')

        if not password:
            raise serializers.ValidationError("Either Password or Profile's secret field is required.")

        return attrs

    def create(self, validated_data):
        password = validated_data.get('password')
        try:
            if password:
                validators.validate_password(password)
        except django_validation_error as e:
            raise ValidationError({"password": e.messages})

        model = self.Meta.model
        instance, is_create = model.objects.get_or_create(is_active=True, email=validated_data['email'])

        if not is_create and instance.is_active:
            raise ConflictException({'email': 'user with this email address already exists. '})

        if password:
            instance.set_password(validated_data['password'])
            instance.save()

        if validated_data.get('profile'):
            try:
                for k, v in validated_data['profile'].items():
                    setattr(instance.profile, k, v)
                instance.profile.save()
            except Exception as e:
                logger.error(e)

        return instance


    def save(self, **kwargs):
        instance = super(UserCreateSerializer, self).save(**kwargs)

        try:
            instance.send_activation_email(self.context.get('request'))
        except Exception as e:
            logger.error(e)

        return instance


class UserSerializer(serializers.ModelSerializer):
    is_online = serializers.BooleanField(read_only=True)
    name = serializers.CharField(read_only=True, source='profile.name')
    email = serializers.EmailField(read_only=True)

    class Meta:
        model = get_user_model()
        exclude = ('password',)



class PayLoadSerializer(serializers.Serializer):
    token = serializers.CharField()
    expiry = serializers.IntegerField()



class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True, required=False)
    password = serializers.CharField(write_only=True)
    force_login = serializers.BooleanField(write_only=True, required=False, default=False)
    user = UserSerializer(read_only=True)
    payload = PayLoadSerializer(read_only=True)

    class Meta:
        error_status_codes = {
            status.HTTP_400_BAD_REQUEST: None,
            status.HTTP_401_UNAUTHORIZED: None,
            status.HTTP_403_FORBIDDEN: None,
            status.HTTP_409_CONFLICT: None
        }

    def __init__(self, *args, **kwargs):
        engine = import_module(settings.SESSION_ENGINE)
        self.SessionStore = engine.SessionStore
        super(UserLoginSerializer, self).__init__(*args, **kwargs)

    @property
    def username_field(self):
        return get_username_field()

    def get_credentials(self, attrs):
        return {
            'username': attrs.get(self.username_field) or User.get_hash(attrs.get('password').encode('utf-8')),
            'password': attrs.get('password')
        }

    def validate(self, attrs):
        credentials = self.get_credentials(attrs)

        request = self.context.get('_request')
        force_login = attrs.get('force_login')
        try:
            user = authenticate(**credentials, request=request)
        except User.MultipleObjectsReturned:
            raise ConflictException(ConflictException(code='DuplicateAccount').get_full_details())

        if user:
            if not user.is_active:
                raise NotAuthenticated(NotAuthenticated().get_full_details())

            token, is_new = ExpiringToken.objects.get_or_create(user=user)

            # 1. 토큰이 만료된경우는 재접속으로 판단.
            # 2. 강제 토큰 갱신의 경우도 재접속으로 판단.
            # 3. 만료되지 않았는데 유저가 접속중이면 동시접속으로 판단 - 제거(주석 처리)
            if token.expired() or force_login:
                token.delete()
                token = ExpiringToken.objects.create(user=user)
            # elif user.is_online:
            #     raise ConflictException(ConflictException(code='AlreadyOnline').get_full_details())

            return {
                'payload': {'token': token.key, 'expiry': token.expiry},
                'user': user
            }
        else:
            raise AuthenticationFailed(AuthenticationFailed().get_full_details())

        return attrs