import logging

from ckan.lib.authenticator import UsernamePasswordAuthenticator
from ckan.lib.cli import MockTranslator
from ckan.model import User
from ckan.common import config
import pylons
from flask import abort
from repoze.who.interfaces import IAuthenticator
from webob.request import Request
from zope.interface import implements
from ckanext.security.cache.login import LoginThrottle
from ckanext.security.model import SecurityTOTP, ReplayAttackException

log = logging.getLogger(__name__)

def get_request_ip_address(request):
    """Retrieves the IP address from the request if possible"""
    remote_addr = request.headers.get('X-Forwarded-For') or request.environ.get('REMOTE_ADDR')
    if remote_addr == None:
        log.critical('X-Forwarded-For header/REMOTE_ADDR missing from request.')

    return remote_addr

def get_login_throttle_key(request, user_name):
    login_throttle_key = get_request_ip_address(request)
    if config.get('ckanext.security.brute_force_key') == 'user_name':
        login_throttle_key = user_name

    return login_throttle_key

class CKANLoginThrottle(UsernamePasswordAuthenticator):
    implements(IAuthenticator)

    def authenticate(self, environ, identity):
        """A username/password authenticator that throttles login request by user name."""
        try:
            user_name = identity['login']
        except KeyError:
            return None

        environ['paste.registry'].register(pylons.translator, MockTranslator())

        if not ('login' in identity and 'password' in identity):
            return None

        # Run through the CKAN auth sequence first, so we can hit the DB
        # in every case and make timing attacks a little more difficult.
        auth_user_name = super(CKANLoginThrottle, self).authenticate(environ, identity)

        login_throttle_key = get_login_throttle_key(Request(environ), user_name)
        if login_throttle_key is None:
            return None

        throttle = LoginThrottle(User.by_name(user_name), login_throttle_key)
        # Check if there is a lock on the requested user, and return None if
        # we have a lock.
        if throttle.is_locked():
            return None

        if auth_user_name is None:
            # Increment the throttle counter if the login failed.
            throttle.increment()

        # if the CKAN authenticator has successfully authenticated the request and the user wasn't locked out above,
        # then check the TOTP parameter to see if it is valid
        if auth_user_name is not None:
            totp_success = self.authenticate_totp(environ, auth_user_name)
            if totp_success:  # if TOTP was successful -- reset the log in throttle
                throttle.reset()
                return totp_success



    def authenticate_totp(self, environ, auth_user):
        totp_challenger = SecurityTOTP.get_for_user(auth_user)

        # if there is no totp configured, don't allow auth
        # shouldn't happen, login flow should create a totp_challenger
        if totp_challenger is None:
            log.info("Login attempted without MFA configured for: {}".format(auth_user))
            return None

        request = Request(environ, charset='utf-8')
        if not ('mfa' in request.POST):
            log.info("Could not get MFA credentials from the request")
            return None

        try:
            result = totp_challenger.check_code(request.POST['mfa'])
        except ReplayAttackException as e:
            log.warning("Detected a possible replay attack for user: {}, context: {}".format(auth_user, e))
            return None

        if result:
            return auth_user

class BeakerRedisAuth(object):
    implements(IAuthenticator)

    def authenticate(self, environ, identity):
        # At this stage, the identity has already been validated from the cookie
        # and redis (use_beaker middleware). We simply return the user id
        # from the identity object if it's there, or None if the user's
        # identity is not verified.
        return identity.get('repoze.who.userid', None)

