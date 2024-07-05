from rest_framework import status
from rest_framework.exceptions import APIException
from django.utils.translation import gettext_lazy as _


class ExpiredException(APIException):
    status_code = status.HTTP_408_REQUEST_TIMEOUT


class TokenInvalid(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _('Invalid token.')
    default_code = 'token_invalid'


class TokenExpired(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _('Token has expired.')
    default_code = 'token_expired'


class DuplicateAccess(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = _('Duplicate Accessed.')
    default_code = 'duplicate_access'


class ConflictException(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = _('Conflicted.')
    default_code = 'item conflicted.'


class PreconditionFailed(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    default_detail = _('Precondition Failed.')
    default_code = 'precondition failed.'


class PreconditionRequired(APIException):
    status_code = status.HTTP_428_PRECONDITION_REQUIRED
    default_detail = _('Precondition Required.')
    default_code = 'precondition required.'
