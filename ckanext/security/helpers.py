from ckan.plugins.toolkit import config
from ckan.common import asbool


def security_disable_totp():
    return asbool(config.get('ckanext.security.disable_totp'))
