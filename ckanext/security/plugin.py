import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.logic.schema

from repoze.who.interfaces import IAuthenticator
from zope.interface import implements

from ckanext.security import schema


class CatalystSecurityPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IRoutes)
    implements(IAuthenticator)

    def update_config(self, config):
        # monkeypatching all user schemas in order to enforce a stronger password
        # policy. I tried mokeypatching `ckan.logic.validators.user_password_validator`
        # instead without success.
        ckan.logic.schema.default_user_schema = schema.default_user_schema
        ckan.logic.schema.user_new_form_schema = schema.user_new_form_schema
        ckan.logic.schema.user_edit_form_schema = schema.user_edit_form_schema
        ckan.logic.schema.default_update_user_schema = schema.default_update_user_schema
        toolkit.add_template_directory(config, 'templates')

    def before_map(self, urlmap):
        userController = 'ckanext.security.controllers:SecureUserController'
        urlmap.redirect('/user/edit/', '/user/edit')
        urlmap.connect('/user/edit', controller=userController, action='edit')
        urlmap.connect('/user/edit/{id:.*}', controller=userController, action='edit', ckan_icon='cog')
        urlmap.connect('/user/reset/{id:.*}', controller=userController, action='perform_reset')
        urlmap.connect('/user/reset', controller=userController, action='request_reset')
        return urlmap

    def after_map(self, urlmap):
        return urlmap

    def authenticate(self, environ, identity):
        # At this stage, the identity has already been validated from the cookie
        # and memcache. We simply return the user id from the identity object.
        return identity.get('repoze.who.userid', None)
