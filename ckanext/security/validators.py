# encoding: utf-8
import string

import six
from ckan import authz
from ckan.common import _, config
from ckan.lib.navl.dictization_functions import Missing, Invalid

DEFAULT_MIN_PASSWORD_LENGTH = 10


def _min_password_length():
    return int(config.get('ckanext.security.min_password_length',
                          DEFAULT_MIN_PASSWORD_LENGTH))


def user_password_validator(key, data, errors, context):
    value = data[key]

    if isinstance(value, Missing):
        pass  # Already handled in core
    elif not isinstance(value, six.string_types):
        raise Invalid(_('Passwords must be strings.'))
    elif value == '':
        pass  # Already handled in core
    else:
        # NZISM compliant password rules
        rules = [
            any(x.isupper() for x in value),
            any(x.islower() for x in value),
            any(x.isdigit() for x in value),
            any(x in string.punctuation for x in value)
        ]
        if len(value) < _min_password_length() or sum(rules) < 3:
            raise Invalid(_("Your password must be {} characters or longer, and consist of at least three"
                            " of the following four character sets: uppercase characters, lowercase characters,"
                            " digits, punctuation & special characters.").format(_min_password_length()))


def old_username_validator(key, data, errors, context):
    # Completely prevents changing of user names
    old_user = authz._get_user(context.get('user'))
    return old_user.name


def ensure_str(value):
    return six.text_type(value)
