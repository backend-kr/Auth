from rest_framework import serializers
from rest_auth.models import TokenModel

from api.versioned.v1.users.serializers import UserSerializer

class TokenSerializer(serializers.ModelSerializer):
    user = UserSerializer()
    payload = serializers.SerializerMethodField()

    class Meta:
        model = TokenModel
        fields = ('user', 'payload')

    def get_payload(self, obj):
        if obj.expired():
            user = obj.user
            obj.delete()
            obj = TokenModel.objects.create(user=user)

        return {'token': obj.key, 'expiry': obj.expiry}