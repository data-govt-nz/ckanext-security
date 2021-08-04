# -*- coding: utf-8 -*-

import ckantoolkit as tk
from flask import Blueprint, make_response

security = Blueprint("security", __name__)


@security.before_request
def before_request():

    # def before_map(self, urlmap):
    #     userController = 'ckanext.security.controllers:SecureUserController'
    #     urlmap.redirect('/user/edit/', '/user/edit')
    #     urlmap.connect('/user/edit', controller=userController,
    #                    action='edit')
    #     urlmap.connect('/user/edit/{id:.*}', controller=userController,
    #                    action='edit', ckan_icon='cog')
    #     urlmap.connect('/user/reset/{id:.*}', controller=userController,
    #                    action='perform_reset')
    #     urlmap.connect('/user/reset', controller=userController,
    #                    action='request_reset')
    #     return urlmap
    # def after_map(self, urlmap):
    #     controller = 'ckanext.security.controllers:MFAUserController'
    #     # Mapping urls for the MFA/TOTP feature
    #     urlmap.connect('/configure_mfa/{id:.*}/new',
    #                    controller=controller,
    #                    action='new')
    #     urlmap.connect('mfa_configure', '/configure_mfa/{id:.*}',
    #                    controller=controller,
    #                    action='configure_mfa')
    #     urlmap.connect('/api/mfa_login',
    #                    controller=controller,
    #                    action='login')
    #     return urlmap
