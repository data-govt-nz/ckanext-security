import string

from ckan import authz
from ckan.common import _
from ckan.lib.navl.dictization_functions import Missing
from ckan.logic import ValidationError


MIN_PASSWORD_LENGTH = 10
MIN_LEN_ERROR = (
    'Your password must be {} characters or longer, and consist of at least '
    'three of the following character sets: uppercase characters, lowercase '
    'characters, digits, punctuation & special characters.'
)


def user_password_validator(key, data, errors, context):
    # joeg: somehow key is a tuple: ('password1', ), but value is a string
    field = key[0]
    value = data[key]

    if isinstance(value, Missing):
        pass  # Already handeled in core
    elif not isinstance(value, basestring):
        raise ValidationError(
            {field: [_('Passwords must be strings.')]},
            error_summary={_('Password'): _('invalid new password')}
        )
    elif value == '':
        pass  # Already handeled in core
    else:
        # NZISM compliant password rules
        rules = [
            any(x.isupper() for x in value),
            any(x.islower() for x in value),
            any(x.isdigit() for x in value),
            any(x in string.punctuation for x in value)
        ]
        if len(value) < MIN_PASSWORD_LENGTH or sum(rules) < 3:
            raise ValidationError(
                {field: [_(MIN_LEN_ERROR.format(MIN_PASSWORD_LENGTH))]},
                error_summary={_('Password'): _('invalid new password')}
            )


def old_username_validator(key, data, errors, context):
    # Completely prevents changing of user names
    old_user = authz._get_user(context.get('user'))
    return old_user.name
