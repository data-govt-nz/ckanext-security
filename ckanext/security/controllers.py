import logging

from ckan import model
from ckan.common import _, c, request, config
from ckan.controllers.user import UserController
from ckan.lib.base import abort, render
from ckan.lib import helpers, mailer
from ckan.logic import (
    NotAuthorized, check_access, get_action, NotFound
)
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
        def set_response(status):
            tk.response.status_int = status
            tk.response.headers.update({'Content-Type': 'application/json'})

        (status, res_data) = utils.login()
        set_response(status)
        return res_data

    def configure_mfa(self, id=None):
        utils.configure_mfa(id)
        return tk.render('security/configure_mfa.html')

    def new(self, id=None):
        utils.new(id)
        helpers.redirect_to('/configure_mfa/{}'.format(id))


# Provide ability to fallback to old behaviour if needed
original_password_reset = UserController.request_reset


class SecureUserController(UserController):
    edit_user_form = 'security/edit_user_form.html'

    def request_reset():
        # Later versions of CKAN core have fixed this behaviour, we default
        # to overriding with our own implementation but allow client to
        # disable if needed
        if tk.asbool(config.get(
                'ckanext.security.disable_password_reset_override')):
            return original_password_reset()

        form_data = utils._get_request_form_data(request)

        # This is a one-to-one copy from ckan core, except for user errors
        # handling. There should be no feedback about whether or not a user
        # is found in the db.
        # Original method is
        # `ckan.controllers.user.UserController.request_reset`
        context = {'model': model, 'session': model.Session, 'user': c.user,
                   'auth_user_obj': c.userobj}
        data_dict = {'id': form_data.get('user')}
        try:
            check_access('request_reset', context)
        except NotAuthorized:
            abort(403, _('Unauthorized to request reset password.'))

        if request.method == 'POST':
            id = form_data.get('user')

            context = {'model': model,
                       'user': c.user,
                       u'ignore_auth': True}

            data_dict = {'id': id}
            user_obj = None
            try:
                get_action('user_show')(context, data_dict)
                user_obj = context['user_obj']
            except NotFound:
                # Try searching the user
                del data_dict['id']
                data_dict['q'] = id

                if id and len(id) > 2:
                    user_list = get_action('user_list')(context, data_dict)
                    if len(user_list) == 1:
                        # This is ugly, but we need the user object for the
                        # mailer,
                        # and user_list does not return them
                        del data_dict['q']
                        data_dict['id'] = user_list[0]['id']
                        get_action('user_show')(context, data_dict)
                        user_obj = context['user_obj']

            helpers.flash_success(_('A reset token has been sent.'))
            if user_obj:
                mailer.send_reset_link(user_obj)
        return render('user/request_reset.html')