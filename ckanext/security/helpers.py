from ckan.common import config
from paste.deploy.converters import asbool


def security_disable_totp():
    return asbool(config.get('ckanext.security.disable_totp'))
