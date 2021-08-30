# -*- coding: utf-8 -*-

import ckan.plugins as p
import ckanext.security.views as views
import ckanext.security.cli as cli


class MixinPlugin(p.SingletonPlugin):
    p.implements(p.IClick)
    p.implements(p.IBlueprint)

    # IBlueprint

    def get_blueprint(self):
        return views.get_blueprints()

    # ICLick

    def get_commands(self):
        return cli.get_commands()