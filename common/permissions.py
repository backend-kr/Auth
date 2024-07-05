from rest_framework import permissions
from rest_framework.permissions import IsAuthenticated

class ModelPermissions(permissions.DjangoModelPermissions):
    perms_map = {
        'OPTIONS': [],
        'HEAD': [],
        'GET': ['%(app_label)s.view_%(model_name)s'],
        'POST': ['%(app_label)s.add_%(model_name)s'],
        'PUT': ['%(app_label)s.change_%(model_name)s'],
        'PATCH': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.delete_%(model_name)s'],
    }

IsAdminUserWithModel = (permissions.IsAdminUser, ModelPermissions,)

class IsContracted(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.contract_set.all().exists()

class IsOwner(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        if request.user:
            if hasattr(view, 'owner_field'):
                return getattr(obj, view.owner_field, None) == request.user
            else:
                return obj == request.user
        return False

class IsOwnerOrAdminUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and (request.user.is_authenticated or request.user.is_staff)

    def has_object_permission(self, request, view, obj):
        if request.user and request.user.is_staff:
            return True
        elif request.user:
            if hasattr(view, 'owner_field'):
                return getattr(obj, view.owner_field, None) == request.user
            else:
                return obj == request.user
        return False

class IsVendorUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_vendor

class IsVendorOrAdminUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and \
               request.user.is_authenticated and \
               (request.user.is_vendor or request.user.is_staff)