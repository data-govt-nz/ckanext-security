import logging

from ckan.controllers.user import UserController
from ckan.plugins import toolkit as tk
from ckanext.security import utils

log = logging.getLogger(__name__)


class MFAUserController(tk.BaseController):
    def __before__(self, action, **env):
        tk.BaseController.__before__(self, action, **env)
        if action == 'login':
            return

        utils.check_user_and_access()

    def login(self):
        return utils.login()

    def configure_mfa(self, id=None):
        return utils.configure_mfa(id)

    def new(self, id=None):
        return utils.new(id)


class SecureUserController(UserController):
    edit_user_form = 'security/edit_user_form.html'

    def _edit_form_to_db_schema(self):
        return utils.edit_form_to_db_schema()

    def request_reset(self):
        return utils.request_reset()
