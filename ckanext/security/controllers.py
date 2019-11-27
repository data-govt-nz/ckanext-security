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
import json

log = logging.getLogger(__name__)


class MFAUserController(tk.BaseController):
    def __before__(self, action, **env):
        tk.BaseController.__before__(self, action, **env)
        if action == 'login':
            return

        context = {'model': model, 'user': c.user,
                   'auth_user_obj': c.userobj}
        check_access('site_read', context)
        if not c.userobj:
            abort(403, _('No user specified'))

    def _fetch_user_or_fail(self, context, data_dict):
        """
        Get user dict or abort request
        :param context:
        :param data_dict: requires an id field
        :return: user_dict: a dictionary of user information based on the supplied query
        """
        try:
            # if the current user can update the target user, then they can manage the totp secret
            log.error(" {}".format(data_dict))
            check_access('user_update', context, {'id': data_dict['id']})
            user_dict = get_action('user_show')(context, {'id': data_dict['id']})
        except NotFound as e:
            tk.redirect_to(controller='user', action='login')
        except NotAuthorized:
            abort(403, _('Not authorized to see this page'))
        return user_dict

    def _setup_totp_template_variables(self, context, data_dict):
        """Populates context with
        is_sysadmin
        totp_challenger_uri
        totp_secret
        """
        c.is_sysadmin = authz.is_sysadmin(c.user)
        c.totp_user_id = data_dict['id']

        user_dict = self._fetch_user_or_fail(context, data_dict)

        c.user_dict = user_dict
        c.is_myself = user_dict['name'] == c.user

        totp_challenger = SecurityTOTP.get_for_user(user_dict['name'])
        if totp_challenger is not None:
            c.totp_secret = totp_challenger.secret
            c.totp_challenger_uri = pyotp.TOTP(totp_challenger.secret)\
                .provisioning_uri(user_dict['name'], issuer_name='CKAN Security Extension')

    def login(self):
        """
        Ajax call to test username/password/mfa code
        """
        tk.response.headers.update({'Content-Type': 'application/json'})
        if request.method != 'POST':
            tk.response.status_int = 405
            return

        identity = request.params
        if not ('login' in identity and 'password' in identity):
            tk.response.status_int = 422
            return

        login = identity['login']
        user = model.User.by_name(login)

        if user is None or not user.is_active() or not user.validate_password(identity['password']):
            log.info('user failed to provide correct credentials')
            tk.response.status_int = 403
            return

        # find or create 2 factor auth record
        totp_challenger = SecurityTOTP.get_for_user(user.name)
        if totp_challenger is None:
            totp_challenger = SecurityTOTP.create_for_user(user.name)

        mfaConfigured = totp_challenger.last_successful_challenge is not None
        res = {}
        if not mfaConfigured:
            res['totpSecret'] = totp_challenger.secret
            res['totpChallengerURI'] = totp_challenger.provisioning_uri

        res['mfaConfigured'] = mfaConfigured

        if identity['mfa']:
            res['mfaCodeValid'] = totp_challenger.check_code(identity['mfa'], verify_only=True)

        return json.dumps(res)

    def configure_mfa(self, id=None):
        """Display the config of the users MFA"""
        context = {
                  'model': model, 'session': model.Session,
                  'user': c.user, 'auth_user_obj': c.userobj
                  }
        # pylons includes the rest of the url in the param, so we need to strip the /new suffix
        user_id = id.replace('/new', '')

        self._setup_totp_template_variables(context, {'id': user_id, 'user_obj': c.userobj})
        return tk.render('security/configure_mfa.html')

    def new(self, id=None):
        """Set up a users new security TOTP credentials"""
        context = {
            'model': model, 'session': model.Session,
            'user': c.user, 'auth_user_obj': c.userobj
        }
        # pylons includes the rest of the url in the param, so we need to strip the /new suffix
        user_id = id.replace('/new', '')

        data_dict = {'id': user_id, 'user_obj': c.userobj}
        user_dict = self._fetch_user_or_fail(context, data_dict)
        SecurityTOTP.create_for_user(user_dict['name'])
        self._setup_totp_template_variables(context, data_dict)
        log.info("Rotated the MFA secret for user {}".format(user_id))
        helpers.redirect_to('mfa_configure', id=user_id)


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
