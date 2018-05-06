import os
import codecs

import webob
from webob.exc import HTTPForbidden

from ckanext.security.cache.clients import CSRFClient

import logging
log = logging.getLogger(__name__)

try:
    from hmac import compare_digest
except ImportError:
    def compare_digest(a, b):
        return a == b


CSRF_ERR = 'CSRF authentication failed. Token missing or invalid.'


class Request(webob.Request):
    def is_secure(self):
        # allow requests which have the x-forwarded-proto of https (inserted by nginx)
        if self.headers.get('X-Forwarded-Proto') == 'https':
            return True 
        return self.scheme == 'https'

    def is_safe(self):
        "Check if the request is 'safe', if the request is safe it will not be checked for csrf"
        # api requests are exempt from csrf checks
        if self.path.startswith("/api"):
            return True
        
        # get/head/options/trace are exempt from csrf checks
        return self.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE')

    def good_referer(self):
        "Returns true if the referrer is https and matching the host"
        if not self.referer:
            return False 
        else:
            match = "https://{}/".format(self.host)
            return self.referer.startswith(match)


class CSRFMiddleware(object):
    COOKIE_NAME = 'csrftoken'

    def __init__(self, app, config):
        self.app = app
        self.cache = CSRFClient()
        self.domain = config['ckanext.security.domain']

    def __call__(self, environ, start_response):
        request = Request(environ)
        self.session = environ['beaker.session']
        self.session.save()

        if self.is_valid(request):
            resp = request.get_response(self.app)
        else:
            resp = HTTPForbidden(CSRF_ERR)

        if 'text/html' in resp.headers['Content-type']:
            resp = self.add_new_token(resp)
        return resp(environ, start_response)

    def is_valid(self, request):
        return request.is_safe() or self.unsafe_request_is_valid(request)

    def unsafe_request_is_valid(self, request):
        return request.is_secure() and request.good_referer() and self.check_cookie(request)

    def check_cookie(self, request):
        token = request.cookies.get(self.COOKIE_NAME, None)

        if token is None:
            # Just in case this is set by an AJAX request
            token = request.cookies.get('X-CSRFToken', None)
        
        csrf_token = self.cache.get(self.session.id)

        if csrf_token == None:
            log.warning('Could not find a csrf token for session id: {}\n{}'.format(self.session.id, request))
            return False

        return compare_digest(str(token), str(csrf_token))

    def add_new_token(self, response):
        token = codecs.encode(os.urandom(32), 'hex')
        self.cache.set(self.session.id, token)
        response.set_cookie(self.COOKIE_NAME, token, httponly=True, overwrite=True, secure=True, domain=self.domain)
        return response
