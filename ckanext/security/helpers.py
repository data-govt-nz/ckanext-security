from ckan.plugins.toolkit import asbool, config


def security_enable_totp():
    return asbool(config.get('ckanext.security.enable_totp', True))
