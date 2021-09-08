import logging

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.logic.schema

from ckanext.security.model import define_security_tables
from ckanext.security import schema
from ckanext.security.resource_upload_validator import validate_upload_type, validate_upload_presence
from ckanext.security.logic import auth, action
from ckanext.security import helpers

log = logging.getLogger(__name__)

class CkanSecurityPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IRoutes)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IResourceController, inherit=True)
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IAuthFunctions)
    plugins.implements(plugins.ITemplateHelpers)

    def update_config(self, config):
        define_security_tables()  # map security models to db schema

        # Monkeypatching all user schemas in order to enforce a stronger password
        # policy. I tried mokeypatching `ckan.logic.validators.user_password_validator`
        # instead without success.
        ckan.logic.schema.default_user_schema = schema.default_user_schema
        ckan.logic.schema.user_new_form_schema = schema.user_new_form_schema
        ckan.logic.schema.user_edit_form_schema = schema.user_edit_form_schema
        ckan.logic.schema.default_update_user_schema = schema.default_update_user_schema

        toolkit.add_template_directory(config, 'templates')
        toolkit.add_resource('fanstatic', 'security')

    def before_map(self, urlmap):
        userController = 'ckanext.security.controllers:SecureUserController'
        urlmap.redirect('/user/edit/', '/user/edit')
        urlmap.connect('/user/edit', controller=userController, action='edit')
        urlmap.connect('/user/edit/{id:.*}', controller=userController, action='edit', ckan_icon='cog')
        urlmap.connect('/user/reset/{id:.*}', controller=userController, action='perform_reset')
        urlmap.connect('/user/reset', controller=userController, action='request_reset')
        return urlmap

    def after_map(self, urlmap):
        controller = 'ckanext.security.controllers:MFAUserController'
        # Mapping urls for the MFA/TOTP feature
        urlmap.connect('/configure_mfa/{id:.*}/new',
                       controller=controller,
                       action='new')
        urlmap.connect('mfa_configure', '/configure_mfa/{id:.*}',
                       controller=controller,
                       action='configure_mfa')
        urlmap.connect('/api/mfa_login',
                       controller=controller,
                       action='login')

        return urlmap

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
            'security_throttle_user_reset': action.security_throttle_user_reset,
            'security_throttle_address_reset': action.security_throttle_address_reset,
            'security_throttle_user_show': action.security_throttle_user_show,
            'security_throttle_address_show': action.security_throttle_address_show,
            'user_update': action.user_update,
        }
    # END Hooks for IActions

    # BEGIN Hooks for IAuthFunctions
    def get_auth_functions(self):
        return {
            'security_throttle_user_reset': auth.security_throttle_user_reset,
            'security_throttle_address_reset': auth.security_throttle_address_reset,
            'security_throttle_user_show': auth.security_throttle_user_show,
            'security_throttle_address_show': auth.security_throttle_address_show,
        }
    # END Hooks for IAuthFunctions

    # BEGIN Hooks for ITemplateHelpers

    def get_helpers(self):
        return {
            'security_disable_totp': helpers.security_disable_totp,
        }
    # END Hooks for ITemplateHelpers
