# encoding: utf-8
import six
import string

from ckan import authz
from ckan.common import _
from ckan.lib.navl.dictization_functions import Missing, Invalid
# (canada fork only): more configs
from ckan.plugins.toolkit import config, asbool

MIN_LEN_ERROR = 'Your password must be {} characters or longer.'
COMPLEXITY_ERROR = (
    'Your password must consist of at least three of the following character sets: '
    'uppercase characters, lowercase characters, digits, punctuation & special characters.'
)


def user_password_validator(key, data, errors, context):
    value = data[key]

    if isinstance(value, Missing):
        pass  # Already handled in core
    elif not isinstance(value, six.string_types):
        raise Invalid(_('Passwords must be strings.'))
    elif value == '':
        pass  # Already handled in core
    else:
        # (canad fork only): better error messages
        # TODO: upstream contrib??
        min_password_length = int(config.get('ckanext.security.min_password_length', 8))
        nzism_compliant = asbool(config.get('ckanext.security.nzism_compliant_passwords', True))
        if len(value) < min_password_length:
            errors[key].append(_(MIN_LEN_ERROR).format(min_password_length))
        if nzism_compliant:
            # NZISM compliant password rules
            rules = [
                any(x.isupper() for x in value),
                any(x.islower() for x in value),
                any(x.isdigit() for x in value),
                any(x in string.punctuation for x in value)
            ]
            if sum(rules) < 3:
                errors[key].append(_(COMPLEXITY_ERROR))


def old_username_validator(key, data, errors, context):
    # Completely prevents changing of user names
    old_user = authz._get_user(context.get('user'))
    return old_user.name


def ensure_str(value):
    return six.text_type(value)
