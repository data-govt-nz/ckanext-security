from builtins import object
import logging
import json

from ckan import authz, model
from ckan.lib.base import abort
from ckan.lib import helpers, mailer
from ckan.logic import (
    NotAuthorized, check_access, get_action, NotFound
)
from ckan.plugins import toolkit as tk
from ckan.plugins.toolkit import request, config, _, c, g
from ckanext.security.authenticator import get_login_throttle_key
from ckanext.security import mailer as secure_mailer
from ckanext.security.model import SecurityTOTP
from ckanext.security.cache.login import LoginThrottle

log = logging.getLogger(__name__)

# Override password reset link
if not tk.asbool(config.get(
                'ckanext.security.disable_password_reset_override')):
    mailer.send_reset_link = secure_mailer.send_reset_link


def check_user_and_access():
    gc = _get_global()
    context = {'model': model, 'user': gc.user, 'auth_user_obj': gc.userobj}
    check_access('site_read', context)
    if not gc.userobj:
        abort(403, _('No user specified'))


def _fetch_user_or_fail(context, data_dict):
    """
    Get user dict or abort request
    :param context:
    :param data_dict: requires an id field
    :return: user_dict: a dictionary of user information based on
        the supplied query
    """
    try:
        # if the current user can update the target user,
        # then they can manage the totp secret
        check_access('user_update', context, {'id': data_dict['id']})
        user_dict = get_action('user_show')(
            context, {'id': data_dict['id']})
    except NotFound:
        tk.redirect_to(controller='user', action='login')
    except NotAuthorized:
        abort(403, _('Not authorized to see this page'))
    return user_dict


def _get_global():
    return g if tk.check_ckan_version(min_version='2.9.0') \
        else c


def _get_template_context():
    class TemplateContext(object):
        pass

    return TemplateContext() if tk.check_ckan_version(min_version='2.9.0') \
        else c


def _get_request_form_data(request):
    """Provides support for form data lookups for Flask and Pylons"""
    if hasattr(request, 'form'):
        return request.form
    else:
        return request.params


def _setup_totp_template_variables(context, data_dict):
    """
    Populates context with:
        user_dict
        is_myself
        is_sysadmin
        totp_user_id
        totp_challenger_uri
        totp_secret
        mfa_test_valid
        mfa_test_invalid
    """
    tc = _get_template_context()
    gc = _get_global()
    form_data = _get_request_form_data(request)

    tc.is_sysadmin = authz.is_sysadmin(gc.user)
    tc.totp_user_id = data_dict['id']

    user_dict = _fetch_user_or_fail(context, data_dict)

    tc.user_dict = user_dict
    tc.is_myself = user_dict['name'] == gc.user

    totp_challenger = SecurityTOTP.get_for_user(user_dict['name'])
    if totp_challenger is not None:
        tc.totp_secret = totp_challenger.secret
        tc.totp_challenger_uri = totp_challenger.provisioning_uri

        mfa_test_code = form_data.get('mfa')
        if request.method == 'POST' and mfa_test_code is not None:
            tc.mfa_test_valid = totp_challenger.check_code(
                mfa_test_code, verify_only=True)
            tc.mfa_test_invalid = not tc.mfa_test_valid
    return tc


def login():
    """Ajax call to test username/password/mfa code"""
    try:
        res = {}
        if request.method != 'POST':
            return (405, json.dumps(res))

        identity = _get_request_form_data(request)
        if not ('login' in identity and 'password' in identity):
            return (422, json.dumps(res))

        on_mfa_form = identity.get('mfa-form-active') == 'true'

        user_name = identity['login']
        user = model.User.by_name(user_name)

        login_throttle_key = get_login_throttle_key(request, user_name)
        if login_throttle_key is None:
            return (403, json.dumps(res))

        throttle = LoginThrottle(user, login_throttle_key)
        locked_out = throttle.is_locked()
        if locked_out:
            log.info(
                '[%s] attempted login while brute force lockout in place',
                user_name
            )

        # Flask-login changed is_active from function to attribute on user
        user_is_active = user is not None and (
           user.is_active() if callable(user.is_active) else user.is_active
        )
        invalid_login = not user_is_active \
            or not user.validate_password(identity['password'])
        if invalid_login:
            # Increment the throttle counter if the login failed.
            throttle.increment()

        if invalid_login or (locked_out and not on_mfa_form):
            log.info('login failed for %s', user_name)
            return (403, json.dumps(res))

        # find or create 2 factor auth record
        totp_challenger = SecurityTOTP.get_for_user(user.name)
        if totp_challenger is None:
            totp_challenger = SecurityTOTP.create_for_user(user.name)

        mfaConfigured = totp_challenger.last_successful_challenge \
            is not None
        if not mfaConfigured:
            res['totpSecret'] = totp_challenger.secret
            res['totpChallengerURI'] = totp_challenger.provisioning_uri

        res['mfaConfigured'] = mfaConfigured
        response_status = 200

        if config.get('ckanext.security.mfa_help_link') is not None:
            res['mfaHelpLink'] = config.get(
                'ckanext.security.mfa_help_link')

        if identity['mfa']:
            code_valid = totp_challenger.check_code(
                identity['mfa'], verify_only=True)
            res['mfaCodeValid'] = code_valid and not locked_out
            if code_valid:
                log.info('Login succeeded for %s', user_name)
            else:
                log.info('User %s supplied invalid 2fa code', user_name)
                response_status = 403
                throttle.increment()

        return (response_status, json.dumps(res))

    except Exception as err:
        log.error('Unhandled error during login: %s', err, exc_info=True)
        return (500, json.dumps({}))


def configure_mfa(id=None):
    """Display the config of the users MFA"""
    gc = _get_global()
    context = {
        'model': model, 'session': model.Session,
        'user': gc.user, 'auth_user_obj': gc.userobj
    }
    # pylons includes the rest of the url in the param,
    # so we need to strip the /new suffix
    user_id = id.replace('/new', '')

    data_dict = {'id': user_id, 'user_obj': gc.userobj}
    tc = _setup_totp_template_variables(context, data_dict)

    if request.method == 'POST':
        if tc.mfa_test_valid:
            helpers.flash_success(_('''That's a valid code. Your authenticator
                app is correctly configured for future use.'''))
        if tc.mfa_test_invalid:
            helpers.flash_error(_('''That's an incorrect code. Try scanning
                the QR code again with your authenticator app.'''))
    return tc


def new(id=None):
    """Set up a user's new security TOTP credentials"""
    gc = _get_global()
    context = {
        'model': model, 'session': model.Session,
        'user': gc.user, 'auth_user_obj': gc.userobj
    }
    # pylons includes the rest of the url in the param,
    # so we need to strip the /new suffix
    user_id = id.replace('/new', '')

    data_dict = {'id': user_id, 'user_obj': gc.userobj}
    user_dict = _fetch_user_or_fail(context, data_dict)
    SecurityTOTP.create_for_user(user_dict['name'])
    log.info("Rotated the 2fa secret for user {}".format(user_id))
    helpers.flash_success(_('''Successfully updated two factor
            authentication secret. Make sure you add the new secret to
            your authenticator app.'''))
