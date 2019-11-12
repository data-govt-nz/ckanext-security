import logging

from ckan.lib.authenticator import UsernamePasswordAuthenticator
from ckan.lib.cli import MockTranslator
from ckan.model import User
import pylons
from flask import abort
from repoze.who.interfaces import IAuthenticator
from webob.request import Request
from zope.interface import implements
from ckanext.security.cache.login import LoginThrottle
from ckanext.security.model import SecurityTOTP, ReplayAttackException

log = logging.getLogger(__name__)


class CKANLoginThrottle(UsernamePasswordAuthenticator):
    implements(IAuthenticator)

    def authenticate(self, environ, identity):
        """A username/password authenticator that throttles login request by IP."""
        try:
            login = identity['login']
        except KeyError:
            return None

        environ['paste.registry'].register(pylons.translator, MockTranslator())

        try:
            remote_addr = Request(environ).headers['X-Forwarded-For']
        except KeyError:
            try:
                remote_addr = environ['REMOTE_ADDR']
            except KeyError:
                log.critical('X-Forwarded-For header/REMOTE_ADDR missing from request.')
                return None

        throttle = LoginThrottle(User.by_name(login), remote_addr)
        if not ('login' in identity and 'password' in identity):
            return None

        # Run through the CKAN auth sequence first, so we can hit the DB
        # in every case and make timing attacks a little more difficult.
        auth_user = super(CKANLoginThrottle, self).authenticate(environ, identity)

        # Check if there is a lock on the requested user, and return None if
        # we have a lock.
        if throttle.check_attempts() is False:
            log.info('User %r (%s) locked out by brute force protection.' % (login, remote_addr))
            throttle.increment()  # Increment so we only send an email the first time around
            return None

        # if the CKAN authenticator has successfully authenticated the request and the user wasn't locked out above,
        # then check the TOTP parameter to see if it is valid

        if auth_user is not None:
            totp_success = self.authenticate_totp(environ, auth_user)
            if totp_success:  # if TOTP was successful -- reset the log in throttle
                throttle.reset()
                return totp_success

        # Increment the throttle counter if the login failed.
        throttle.increment()

    def authenticate_totp(self, environ, auth_user):
        # IF the user has MFA setup - do the MFA challenge
        # else
        totp_challenger = SecurityTOTP.get_for_user(auth_user)


        # if there is no totp configured -- just let the user auth
        if totp_challenger is None:
            log.info("Logged in a user without configured MFA auth {}".format(auth_user))
            return auth_user

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

