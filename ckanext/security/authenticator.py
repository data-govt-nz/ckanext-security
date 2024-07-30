from builtins import object
import logging
from typing import Any, Union

from ckan.types import Response
from ckan.lib.authenticator import default_authenticate
from ckan.model import User
import ckan.plugins as p
from ckan.plugins.toolkit import \
    request, config, current_user, base, login_user, h, _, asbool
from ckan.views.user import next_page_or_default, rotate_token

from ckanext.security.cache.login import LoginThrottle
from ckanext.security.helpers import security_enable_totp
from ckanext.security.model import SecurityTOTP, ReplayAttackException

# (canada fork only): enforce strong passwords at login
# TODO: upstream contrib??
from ckanext.security.schema import force_strong_password_at_login_schema
from ckan.lib.navl.dictization_functions import validate
from ckan import model
from ckan.lib.mailer import create_reset_key

log = logging.getLogger(__name__)


def get_request_ip_address(request):
    """Retrieves the IP address from the request if possible"""
    remote_addr = request.headers.get('X-Forwarded-For') or \
        request.environ.get('REMOTE_ADDR')
    if remote_addr is None:
        log.critical(
            'X-Forwarded-For header/REMOTE_ADDR missing from request.')

    return remote_addr


def get_login_throttle_key(request, user_name):
    login_throttle_key = get_request_ip_address(request)
    if config.get('ckanext.security.brute_force_key') == 'user_name':
        login_throttle_key = user_name

    return login_throttle_key


def get_user_throttle(user_name):
    if config.get('ckanext.security.brute_force_key') != 'user_name':
        return {}
    return LoginThrottle(User.by_name(user_name), user_name).get()


def get_address_throttle(address):
    if config.get('ckanext.security.brute_force_key') == 'user_name':
        return {}
    return LoginThrottle(None, address).get()


def reset_user_throttle(user_name):
    if config.get('ckanext.security.brute_force_key') != 'user_name':
        return
    # (canada fork only): return value of throttle
    return LoginThrottle(User.by_name(user_name), user_name).reset()


def reset_address_throttle(address):
    if config.get('ckanext.security.brute_force_key') == 'user_name':
        return
    LoginThrottle(None, address).reset()


def reset_totp(user_name):
    SecurityTOTP.create_for_user(user_name)


def authenticate(identity):
    """A username/password authenticator that throttles login request
    by user name, ie only a limited number of attempts can be made
    to log into a specific account within a period of time."""

    # Run through the CKAN auth sequence first, so we can hit the DB
    # in every case and make timing attacks a little more difficult.
    ckan_auth_result = default_authenticate(identity)

    try:
        user_name = identity['login']
    except KeyError:
        return None

    login_throttle_key = get_login_throttle_key(
        request, user_name)
    if login_throttle_key is None:
        return None

    # (canada fork only): enforce strong passwords at login
    # TODO: upstream contrib??
    user_obj = User.by_name(user_name)
    throttle = LoginThrottle(user_obj, login_throttle_key)
    # Check if there is a lock on the requested user, and abort if
    # we have a lock.
    if throttle.is_locked():
        return None

    if ckan_auth_result is None:
        # Increment the throttle counter if the login failed.
        throttle.increment()
        return None

    # totp authentication is enabled by default for all users
    # totp can be disabled, if needed, by setting
    # ckanext.security.enable_totp to false in configurations
    if not security_enable_totp():
        # (canada fork only): reset throttle after successful authentication
        # TODO: upstream contrib??
        if ckan_auth_result:
            throttle.reset()
            # (canada fork only): enforce strong passwords at login
            # TODO: upstream contrib??
            if asbool(config.get('ckanext.security.force_strong_passwords_at_login', False)):
                data, errors = validate({'name': user_name, 'password': identity['password']},
                                        force_strong_password_at_login_schema(), {'user': user_name,
                                                                                  'user_obj': user_obj,
                                                                                  'model': model})
                if errors and 'password' in errors:
                    create_reset_key(user_obj)
                    return {'WEAK_PASS': h.redirect_to('user.perform_reset', id=user_obj.id, key=user_obj.reset_key)}
        return ckan_auth_result

    # if the CKAN authenticator has successfully authenticated
    # the request and the user wasn't locked out above,
    # then check the TOTP parameter to see if it is valid
    totp_success = authenticate_totp(user_name)
    # if TOTP was successful -- reset the log in throttle
    if totp_success:
        throttle.reset()
        return ckan_auth_result
    else:
        # This means that the login form has been submitted
        # with an invalid TOTP code, bypassing the ajax
        # login() workflow in utils.login.
        # The username and password were fine, but the 2fa
        # code was missing or invalid
        throttle.increment()
        return None


def authenticate_totp(auth_user):
    totp_challenger = SecurityTOTP.get_for_user(auth_user)

    # if there is no totp configured, don't allow auth
    # shouldn't happen, login flow should create a totp_challenger
    if totp_challenger is None:
        log.info(
            "Login attempted without MFA configured for: %s",
            auth_user)
        return None

    if not ('mfa' in request.form):
        log.info("Could not get MFA credentials from the request")
        return None

    try:
        result = totp_challenger.check_code(request.form['mfa'])
    except ReplayAttackException as e:
        log.warning(
            "Detected a possible replay attack for user: %s, context: %s",
            auth_user, e)
        return None

    if result:
        return auth_user


def login() -> Union[Response, str]:
    """Override the CKAN default login functionality to provide
    Throttle and MFA protection"""
    extra_vars: dict[str, Any] = {}

    if current_user.is_authenticated:
        return base.render("user/logout_first.html", extra_vars)

    if request.method == "POST":
        username_or_email = request.form.get("login")
        password = request.form.get("password")
        _remember = request.form.get("remember")

        identity = {
            u"login": username_or_email,
            u"password": password
        }

        user_obj = authenticate(identity)
        if user_obj:
            # (canada fork only): enforce strong passwords at login
            # TODO: upstream contrib??
            if isinstance(user_obj, dict) and user_obj.get('WEAK_PASS', False):
                # FIXME: revise flash message
                h.flash_error(_('Your current password is too weak. Please create a new password before logging in again.'))
                return user_obj.get('WEAK_PASS')
            next = request.args.get('next', request.args.get('came_from'))
            if _remember:
                from datetime import timedelta
                duration_time = timedelta(milliseconds=int(_remember))
                login_user(user_obj, remember=True, duration=duration_time)
                rotate_token()
                return next_page_or_default(next)
            else:
                login_user(user_obj)
                rotate_token()
                return next_page_or_default(next)
        else:
            err = _(u"Login failed. Bad username or password.")
            h.flash_error(err)
            return base.render("user/login.html", extra_vars)

    return base.render("user/login.html", extra_vars)


class CKANLoginThrottle():
    p.implements(p.IAuthenticator)

    def authenticate(self, environ, identity):
        return authenticate(identity)


class BeakerRedisAuth(object):
    p.implements(p.IAuthenticator)

    def authenticate(self, environ, identity):
        # At this stage, the identity has already been validated from
        # the cookie and redis (use_beaker middleware). We simply return
        # the user id from the identity object if it's there, or None if
        # the user's identity is not verified.
        return identity.get('repoze.who.userid', None)
