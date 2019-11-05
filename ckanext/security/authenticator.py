import logging
from urllib import urlencode
from urlparse import urlparse, parse_qs, urlunparse

from ckan.lib.authenticator import UsernamePasswordAuthenticator
from ckan.lib.cli import MockTranslator
from ckan.model import User

import pylons
from paste.request import construct_url
from repoze.who.interfaces import IAuthenticator, IChallenger
from webob.exc import HTTPFound
from webob.request import Request
from zope.interface import implements

from ckanext.security.cache.login import LoginThrottle


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

        # If the CKAN authenticator as successfully authenticated the request
        # and the user wasn't locked out above, reset the throttle counter and
        # return the user object.
        if auth_user is not None:
            throttle.reset()
            return auth_user

        # Increment the throttle counter if the login failed.
        throttle.increment()


class BeakerRedisAuth(object):
    implements(IAuthenticator)

    def authenticate(self, environ, identity):
        # At this stage, the identity has already been validated from the cookie
        # and redis (use_beaker middleware). We simply return the user id
        # from the identity object if it's there, or None if the user's
        # identity is not verified.
        return identity.get('repoze.who.userid', None)


class CKANTOTPChallenge(object):
    implements(IChallenger)
    def __init__(self):
        self.logout_handler_path = '/'
        self.post_logout_url = '/'
        self.login_form_url = '/'


    # extended from repoze friendlyform implementation
    def challenge(self, environ, status, app_headers, forget_headers):
        """
        Override the parent's challenge to avoid challenging the user on
        logout, introduce a post-logout page and/or pass the login counter
        to the login form.

        """
        url_parts = list(urlparse(self.login_form_url))
        query = url_parts[4]
        query_elements = parse_qs(query)
        came_from = environ.get('came_from', construct_url(environ))
        query_elements['came_from'] = came_from
        url_parts[4] = urlencode(query_elements, doseq=True)
        login_form_url = urlunparse(url_parts)
        login_form_url = self._get_full_path(login_form_url, environ)
        destination = login_form_url
        # Configuring the headers to be set:
        cookies = [(h, v) for (h, v) in app_headers if h.lower() == 'set-cookie']
        headers = forget_headers + cookies

        if environ['PATH_INFO'] == self.logout_handler_path:
            # Let's log the user out without challenging.
            came_from = environ.get('came_from')
            if self.post_logout_url:
                # Redirect to a predefined "post logout" URL.
                destination = self._get_full_path(self.post_logout_url,
                                                  environ)
                if came_from:
                    destination = self._insert_qs_variable(
                        destination, 'came_from', came_from)
            else:
                # Redirect to the referrer URL.
                script_name = environ.get('SCRIPT_NAME', '')
                destination = came_from or script_name or '/'

        elif 'repoze.who.logins' in environ:
            # Login failed! Let's redirect to the login form and include
            # the login counter in the query string
            environ['repoze.who.logins'] += 1
            # Re-building the URL:
            destination = self._set_logins_in_url(destination,
                                                  environ['repoze.who.logins'])

        # If no challenge then redirect to the endpoint
        return HTTPFound(location=destination, headers=headers)

    # Also vendored from
    def _get_full_path(self, path, environ):
        """
        Return the full path to ``path`` by prepending the SCRIPT_NAME.

        If ``path`` is a URL, do nothing.

        """
        if path.startswith('/'):
            path = environ.get('SCRIPT_NAME', '') + path
        return path

    def _set_logins_in_url(self, url, logins):
        """
        Insert the login counter variable with the ``logins`` value into
        ``url`` and return the new URL.

        """
        return self._insert_qs_variable(url, self.login_counter_name, logins)

    def _insert_qs_variable(self, url, var_name, var_value):
        """
        Insert the variable ``var_name`` with value ``var_value`` in the query
        string of ``url`` and return the new URL.

        """
        url_parts = list(urlparse(url))
        query_parts = parse_qs(url_parts[4])
        query_parts[var_name] = var_value
        url_parts[4] = urlencode(query_parts, doseq=True)
        return urlunparse(url_parts)
