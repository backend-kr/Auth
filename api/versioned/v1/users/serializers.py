import logging

from django.contrib.auth import get_user_model, authenticate, password_validation as validators
from django.contrib.sites.models import Site
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError as django_validation_error

from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from api.bases.users.models import Profile, Image
from common.exceptions import ConflictException

logger = logging.getLogger('django.server')

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
