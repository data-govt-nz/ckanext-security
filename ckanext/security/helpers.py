from ckan.common import config
from paste.deploy.converters import asbool


def security_enable_totp():
    return asbool(config.get('ckanext.security.enable_totp', True))
