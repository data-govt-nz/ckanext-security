import os
import codecs
import hmac

import webob
from webob.exc import HTTPForbidden


class Request(webob.Request):
    def is_secure(self):
        return self.scheme == 'https'

    def is_safe(self):
        return self.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE')

    def good_referer(self):
        pass


class CSRFMiddleware(object):
    COOKIE_NAME = 'csrftoken'

    def __init__(self, app, config):
        self.app = app
        # get a setting, ie memcached session
        #self.csrf_secret = config.get('csrf_secret', 'Some Secret!!!')

    def __call__(self, environ, start_response):
        request = Request(environ)
        session = environ['beaker.session']

        if self.is_valid(request):
            response = request.get_response(self.app)
            return self.add_new_token(response)
        raise HTTPForbidden('CSRF authentication failed. Token missing or invalid.')

    def is_valid(self, request):
        if request.is_safe():
            return True  # Valid always
        elif request.is_secure() and request.good_referer() and self.check_cookie(request):
            return True
        return False

    def check_cookie(self, request):
        token = request.cookies.get(COOKIE_NAME, None)
        if token is None:
            # Just in case this is set by an AJAX request
            token = request.cookies.get('X-CSRFToken', None)
        return hmac.compare_digest(token, self.self.cache.get(self.session_id))

    def add_new_token(self, response):
        token = codecs.encode(os.urandom(64), 'hex')
        self.cache.add(self.session_id, token)
        response.set_cookie(COOKIE_NAME, token, httponly=True, overwrite=True, secure=True)
        return response
