import logging
import ckan.plugins as p

from ckan.plugins import toolkit as tk
from ckanext.security.model import define_security_tables
from ckanext.security.resource_upload_validator import (
    validate_upload
)
from ckanext.security import validators
from ckanext.security.logic import auth, action
from ckanext.security.helpers import security_enable_totp

from ckanext.security.plugin.flask_plugin import MixinPlugin

log = logging.getLogger(__name__)


class CkanSecurityPlugin(MixinPlugin, p.SingletonPlugin):
    p.implements(p.IConfigurer)
    p.implements(p.IResourceController, inherit=True)
    p.implements(p.IActions)
    p.implements(p.IAuthFunctions)
    p.implements(p.ITemplateHelpers)
    p.implements(p.IValidators, inherit=True)

    # BEGIN Hooks for IConfigurer

    def update_config(self, config):
        define_security_tables()  # map security models to db schema

        # (canada fork only): remove monkey patching
        # TODO: upstream contrib??

        tk.add_template_directory(config, '../templates')
        tk.add_resource('../fanstatic', 'security')

    # END Hooks for IConfigurer

    # BEGIN Hooks for IValidators

    def get_validators(self):
        # (canada fork only): implement IValidators instead of monkey patching
        # TODO: upstream contrib??
        return {
            'user_password_validator': validators.user_password_validator,
            'old_username_validator': validators.old_username_validator,
        }

    # END Hooks for IValidators

    # BEGIN Hooks for IResourceController

    # CKAN < 2.10
    def before_create(self, context, resource):
        validate_upload(resource)

    def before_update(self, context, current, resource):
        validate_upload(resource)

    # CKAN >= 2.10
    def before_resource_create(self, context, resource):
        validate_upload(resource)

    def before_resource_update(self, context, current, resource):
        validate_upload(resource)

    # END Hooks for IResourceController

    # BEGIN Hooks for IActions

    def get_actions(self):
        return {
            'security_throttle_user_reset':
                action.security_throttle_user_reset,
            'security_throttle_address_reset':
                action.security_throttle_address_reset,
            'security_throttle_user_show':
                action.security_throttle_user_show,
            'security_throttle_address_show':
                action.security_throttle_address_show,
            'security_reset_totp':
                action.security_reset_totp,
            'user_update':
                action.user_update,
        }
    # END Hooks for IActions

    # BEGIN Hooks for IAuthFunctions

    def get_auth_functions(self):
        return {
            'security_throttle_user_reset':
                auth.security_throttle_user_reset,
            'security_throttle_address_reset':
                auth.security_throttle_address_reset,
            'security_throttle_user_show':
                auth.security_throttle_user_show,
            'security_throttle_address_show':
                auth.security_throttle_address_show,
            'security_reset_totp':
                auth.security_reset_totp,
        }
    # END Hooks for IAuthFunctions

    # ITemplateHelpers

    def get_helpers(self):
        return {
            'check_ckan_version': tk.check_ckan_version,
            'security_enable_totp': security_enable_totp,
        }
