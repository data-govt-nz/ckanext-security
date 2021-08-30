import logging
import ckan.plugins as p

from ckanext.security import schema as ext_schema
from ckan.plugins import toolkit as tk
from ckan.logic import schema as core_schema
from ckanext.security.model import define_security_tables
from ckanext.security.resource_upload_validator import (
    validate_upload_type, validate_upload_presence
)
from ckanext.security.logic import auth, action

try:
    tk.requires_ckan_version("2.9")
except tk.CkanVersionException:
    from ckanext.security.plugin.pylons_plugin import MixinPlugin
else:
    from ckanext.security.plugin.flask_plugin import MixinPlugin

log = logging.getLogger(__name__)


class CkanSecurityPlugin(MixinPlugin, p.SingletonPlugin):
    p.implements(p.IConfigurer)
    p.implements(p.IResourceController, inherit=True)
    p.implements(p.IActions)
    p.implements(p.IAuthFunctions)
    p.implements(p.ITemplateHelpers)

    # BEGIN Hooks for IConfigurer

    def update_config(self, config):
        define_security_tables()  # map security models to db schema

        # Monkeypatching all user schemas in order to enforce a stronger
        # password policy. I tried monkeypatching
        # `ckan.logic.validators.user_password_validator` instead
        # without success.
        core_schema.default_user_schema = \
            ext_schema.default_user_schema
        core_schema.user_new_form_schema = \
            ext_schema.user_new_form_schema
        core_schema.user_edit_form_schema = \
            ext_schema.user_edit_form_schema
        core_schema.default_update_user_schema = \
            ext_schema.default_update_user_schema

        tk.add_template_directory(config, '../templates')
        tk.add_resource('../fanstatic', 'security')

    # END Hooks for IConfigurer

    # BEGIN Hooks for IResourceController

    def before_create(self, context, resource):
        validate_upload_presence(resource)
        validate_upload_type(resource)
        pass

    def before_update(self, context, current, resource):
        validate_upload_presence(resource)
        validate_upload_type(resource)
        pass

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
        }
