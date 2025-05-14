from ckan.plugins.toolkit import _
from ckan.plugins.toolkit import asbool, config
import string, secrets

from ckanext.security.validators import _min_password_length, PASSWORD_ERROR

TABU_LIST_HINT = "Your password must not be the same as any of your last {} passwords."


def security_enable_totp():
    return asbool(config.get('ckanext.security.enable_totp', True))


def password_rules_hint():
    """ Return a description of the password rules """
    min_password_length = _min_password_length()
    password_hint = _(PASSWORD_ERROR).format(min_password_length, string.punctuation)

    # if enabled, add a hint about tabu list passwords
    tabulist_item_count = config.get('ckanext.security.tabulist_item_count')
    if tabulist_item_count and int(tabulist_item_count) > 0:
        return password_hint + " " + _(TABU_LIST_HINT).format(tabulist_item_count)

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
