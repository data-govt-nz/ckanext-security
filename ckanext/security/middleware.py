import os
import codecs

import webob
from webob.exc import HTTPForbidden

from ckanext.security.cache.clients import MemcachedCSRFClient

try:
    from hmac import compare_digest
except ImportError:
    def compare_digest(a, b):
        return a == b


CSRF_ERR = 'CSRF authentication failed. Token missing or invalid.'


class Request(webob.Request):
    def is_secure(self):
        return self.scheme == 'https'

    def is_safe(self):
        return self.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE')

    def good_referer(self):
        return self.referer.startswith("https://{}/".format(self.host))


class CSRFMiddleware(object):
    COOKIE_NAME = 'csrftoken'

    def __init__(self, app, config):
        self.app = app
        self.cache = MemcachedCSRFClient()
        self.domain = config['ckanext.security.domain']

    def __call__(self, environ, start_response):
        request = Request(environ)
        self.session = environ['beaker.session']
        self.session.save()

        resp = request.get_response(self.app) if self.is_valid(request) else HTTPForbidden(CSRF_ERR)
        return self.add_new_token(resp)(environ, start_response)

    def is_valid(self, request):
        return request.is_safe() or self.unsafe_request_is_valid(request)

    def unsafe_request_is_valid(self, request):
        return request.is_secure() and request.good_referer() and self.check_cookie(request)

    def check_cookie(self, request):
        token = request.cookies.get(self.COOKIE_NAME, None)

        if token is None:
            # Just in case this is set by an AJAX request
            token = request.cookies.get('X-CSRFToken', None)
        return compare_digest(token, self.cache.get(self.session.id))

    def add_new_token(self, response):
        token = codecs.encode(os.urandom(32), 'hex')
        self.cache.set(self.session.id, token)
        response.set_cookie(self.COOKIE_NAME, token, httponly=True, overwrite=True, secure=True, domain=self.domain)
        return response
