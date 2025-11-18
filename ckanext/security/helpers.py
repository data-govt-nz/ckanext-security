from ckan.plugins.toolkit import _
from ckan.plugins.toolkit import asbool, config
import string, secrets

from ckanext.security.validators import _min_password_length, PASSWORD_ERROR

BLACKLIST_HINT = "Your password must not be the same as any of your last {} passwords."


def security_enable_totp():
    return asbool(config.get('ckanext.security.enable_totp', True))


def password_rules_hint():
    """ Return a description of the password rules """
    min_password_length = _min_password_length()
    password_hint = _(PASSWORD_ERROR).format(min_password_length, string.punctuation)

    # if enabled, add a hint about blacklist passwords
    blacklist_item_count = config.get('ckanext.security.blacklist_item_count')
    if blacklist_item_count and int(blacklist_item_count) > 0:
        return password_hint + " " + _(BLACKLIST_HINT).format(blacklist_item_count)

    return password_hint


def generate_password():
    """ Generate a random password that complies with the password rules """

    # draft a new password of the minimum length
    min_password_length = _min_password_length()
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(min_password_length))

    # enhance password to absolutely comply with password rules
    return password + \
        secrets.choice(string.ascii_lowercase) + \
        secrets.choice(string.ascii_uppercase) + \
        secrets.choice(string.digits) + \
        secrets.choice(string.punctuation)
