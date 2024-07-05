from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
import re


class SpecialCharacterPasswordValidator(object):

    def validate(self, password, user=None):
        if not re.search('[\W_]+', password):
            raise ValidationError(
                _("This password doesn't have special character."),
                code='password_no_have_special_character',
            )

    def get_help_text(self):
        return _("Your password must have one or more special character.")


class AlphabetPasswordValidator(object):
    def validate(self, password, user=None):
        if password.isalpha():
            raise ValidationError(
                _("This password contains all alphabet."),
                code='password_all_alphabet',
            )

    def get_help_text(self):
        return _("Your password must have number and special character.")


class PreviousSamePasswordValidator(object):
    def validate(self, password, user=None):

            if user and user.check_password(password):
                raise ValidationError(
                    _("This password same from previous password."),
                    code='password_already_used',
                )

    def get_help_text(self):
        return _("Your password must not equal previous password.")