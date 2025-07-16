# encoding: utf-8
import string

import six
from ckan import authz
from ckan.common import _, config
from ckan.lib.navl.dictization_functions import Missing, Invalid
from ckan.plugins import toolkit as tk
from ckanext.security.constants import PLUGIN_EXTRAS_BLACKLIST_KEY
from passlib.hash import pbkdf2_sha512

DEFAULT_MIN_PASSWORD_LENGTH = 10

PASSWORD_ERROR = ("Your password must be {} characters or longer, and consist of at least three" +
                  " of the following four character sets: uppercase characters, lowercase characters," +
                  " digits, punctuation & special characters ({}).")


def _min_password_length():
    return int(config.get('ckanext.security.min_password_length',
                          DEFAULT_MIN_PASSWORD_LENGTH))


def _user_is_editing_self(context):
    # user "default" is used when doing administrative things from CLI.
    if 'user_obj' in context:
        return context['user'] != 'default' and (context['user'] == context['user_obj'].name)

    return False


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
            raise Invalid(_(PASSWORD_ERROR).format(_min_password_length(), string.punctuation))

        # Check that the new password is not on the blacklist
        blacklist_item_count = tk.asint(config.get('ckanext.security.blacklist_item_count', 0))

        # feature enabled? Check needed, because feature could be disabled later
        if blacklist_item_count > 0 and _user_is_editing_self(context):
            if _password_in_blacklist(context, value):
                raise Invalid(_("Your password is not allowed. Please choose a different one."))


def _password_in_blacklist(context, new_password_plain):
    """Return True, if the new password can verify any hash from the blacklist -> then it must be used before."""
    model = context['model']
    user_obj = model.User.get(context['user'])

    if user_obj.plugin_extras and PLUGIN_EXTRAS_BLACKLIST_KEY in user_obj.plugin_extras:
        password_blacklist = user_obj.plugin_extras[PLUGIN_EXTRAS_BLACKLIST_KEY]
        for entry in password_blacklist:
            if entry and pbkdf2_sha512.verify(new_password_plain, entry):
                return True

    return False


def old_username_validator(key, data, errors, context):
    # Completely prevents changing of user names
    old_user = authz._get_user(context.get('user'))
    return old_user.name


def ensure_str(value):
    return six.text_type(value)
