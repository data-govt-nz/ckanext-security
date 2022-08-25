# -*- coding: utf-8 -*-

import ckan.plugins as p


class MixinPlugin(p.SingletonPlugin):
    p.implements(p.IRoutes)

    def before_map(self, urlmap):
        userController = 'ckanext.security.controllers:SecureUserController'
        urlmap.connect('/user/reset', controller=userController,
                       action='request_reset')

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
