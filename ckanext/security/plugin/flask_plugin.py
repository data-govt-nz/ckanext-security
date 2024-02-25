# -*- coding: utf-8 -*-

import ckan.plugins as p
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

    def authenticate(self, identity):
        return authenticator.authenticate(identity)

    # Delete session cookie information
    def logout(self):
        session.invalidate()
