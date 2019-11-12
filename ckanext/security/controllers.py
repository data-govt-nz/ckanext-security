import logging

import pyotp
from ckan import authz, model

from ckan.common import _, c, request
from ckan.controllers.user import UserController
from ckan.lib.base import abort, render
from ckan.lib import helpers
from ckan.lib.navl.dictization_functions import Invalid
from ckan.logic import schema, NotAuthorized, check_access, get_action, NotFound

from ckanext.security import mailer
from ckanext.security.validators import old_username_validator
from ckanext.security.model import SecurityTOTP
from ckan.plugins import toolkit as tk

log = logging.getLogger(__name__)


class MFAUserController(tk.BaseController):
    def __before__(self, action, **env):
        tk.BaseController.__before__(self, action, **env)
        context = {'model': model, 'user': c.user,
                   'auth_user_obj': c.userobj}
        check_access('site_read', context)
        if not c.userobj:
            abort(403, _('No user specified'))
        check_access('user_update', context, {'id': c.userobj.id})

    def _setup_template_variables(self, context, data_dict):
        c.is_sysadmin = authz.is_sysadmin(c.user)
        try:
            user_dict = get_action('user_show')(context, data_dict)
        except NotFound:
            tk.flash_error(_('Not authorized to see this page'))
            tk.redirect_to(controller='user', action='login')
        except NotAuthorized:
            abort(403, _('Not authorized to see this page'))

        c.user_dict = user_dict
        c.is_myself = user_dict['name'] == c.user
    #     TODO fetch from the model..

        totp_challenger = SecurityTOTP.get_for_user(user_dict['name'])
        if totp_challenger is not None:
            c.totp_challenger_uri = pyotp.TOTP(totp_challenger.secret).provisioning_uri(user_dict['name'], issuer_name='Ckan Security Extension')


    def configure_mfa(self, id=None):
        context = {
                  'model': model, 'session': model.Session,
                  'user': c.user, 'auth_user_obj': c.userobj
                  }

        self._setup_template_variables(context, {'id': id, 'user_obj': c.userobj})
        return tk.render('security/configure_mfa.html')


class SecureUserController(UserController):
    edit_user_form = 'security/edit_user_form.html'

    def _edit_form_to_db_schema(self):
        form_schema = schema.user_edit_form_schema()
        form_schema['name'] += [old_username_validator]
        return form_schema


    def request_reset(self):
        # This is a one-to-one copy from ckan core, except for user errors
        # handling. There should be no feedback about whether or not a user
        # is found in the db.
        # Original method is `ckan.controllers.user.UserController.request_reset`
        context = {'model': model, 'session': model.Session, 'user': c.user,
                   'auth_user_obj': c.userobj}
        data_dict = {'id': request.params.get('user')}
        try:
            check_access('request_reset', context)
        except NotAuthorized:
            abort(403, _('Unauthorized to request reset password.'))

        if request.method == 'POST':
            id = request.params.get('user')

            context = {'model': model,
                       'user': c.user}

            data_dict = {'id': id}
            user_obj = None
            try:
                user_dict = get_action('user_show')(context, data_dict)
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
                        user_dict = get_action('user_show')(context, data_dict)
                        user_obj = context['user_obj']

            helpers.flash_success(_('A reset token has been sent.'))
            if user_obj:
                mailer.send_reset_link(user_obj)
        return render('user/request_reset.html')
