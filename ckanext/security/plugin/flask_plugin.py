# -*- coding: utf-8 -*-

import ckan.plugins as p
from ckan.plugins import toolkit as tk
from ckanext.security import views, cli, authenticator
from ckan.common import session


class MixinPlugin(p.SingletonPlugin):
    p.implements(p.IClick)
    p.implements(p.IBlueprint)
    p.implements(p.IAuthenticator, inherit=True)

    # IBlueprint

    def get_blueprint(self):
        return views.get_blueprints()

    # ICLick

    def get_commands(self):
        return cli.get_commands()

    # IAuthenticator

    def login(self):
        return authenticator.login()

    # Delete session cookie information
    def logout(self):
        # CKAN 2.11+ uses Flask-Session which has clear() instead of invalidate()
        if tk.check_ckan_version(min_version='2.11'):
            session.clear()
        else:
            session.invalidate()
