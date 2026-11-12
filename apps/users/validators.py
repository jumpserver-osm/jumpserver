import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


username_pattern = re.compile(r'^[a-zA-Z0-9_@.\-\u4e00-\u9fff]+$')
invalid_username_code = 'invalid_username'
invalid_username_login_msg = _("The username is non-compliant")


def validate_username(username):
    if isinstance(username, str) and username_pattern.fullmatch(username):
        return

    username = username if isinstance(username, str) else ''
    invalid_chars = re.sub(r'[a-zA-Z0-9_@.\-\u4e00-\u9fff]', '', username)
    invalid_chars = ''.join(sorted(set(invalid_chars)))
    raise ValidationError(
        _("Username contains invalid characters: %(chars)s") % {'chars': invalid_chars},
        code=invalid_username_code,
    )


def get_validation_error_message(error):
    return error.messages[0]


def get_login_error_message(error):
    if getattr(error, 'code', None) == invalid_username_code:
        return str(invalid_username_login_msg)
    return get_validation_error_message(error)
