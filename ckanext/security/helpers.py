from ckan.plugins.toolkit import asbool, config
from ckan import model


def security_enable_totp():
    return asbool(config.get('ckanext.security.enable_totp', True))

def security_get_user(user_name):
    user = model.User.by_name(user_name)
    if not user:
        user = model.User.by_email(user_name)
    return user
