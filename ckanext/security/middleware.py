import anti_csrf
import webob
from webob.exc import HTTPForbidden

import logging

log = logging.getLogger(__name__)


CSRF_ERR = 'CSRF authentication failed. Token missing or invalid.'


class Request(webob.Request):
    def __init__(self, environ):
        super(Request, self).__init__(environ)
        self.token = self._get_post_token()

    def is_secure(self):
        """ Check if the request uses HTTPS,
        either directly or via Nginx."""
        if self.headers.get('X-Forwarded-Proto') == 'https':
            return True
        return self.scheme == 'https'

    def is_safe(self):
        """ Check if the request is 'safe'.
        If so, it will not be checked for CSRF."""
        # api requests are exempt from csrf checks
        if self.path.startswith("/api"):
            return True

        # get/head/options/trace are exempt from csrf checks
        return self.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE')

    def good_referer(self, domain):
        """ Check whether the referrer header is HTTPS and matches the host.
        """
        if not self.referer:
            return False
        else:
            match = "https://{}".format(domain)
            return self.referer.startswith(match)

    def good_origin(self, domain):
        """Check if the origin header is present and matches the header.
        :param domain: string: the expected origin domain
        :return: boolean: true if the origin header is present and
         matches the expected domain
        """
        origin = self.headers.get('origin', None)
        if not origin:
            log.warning(
                "Potentially unsafe request is missing the Origin header")
            return True
        else:
            match = "https://{}".format(domain)
            return origin.startswith(match)

    def _get_post_token(self):
        """Retrieve the token provided by the client, or return None
        if not present.

        This is normally a single 'token' parameter in the POST body.
        However, for compatibility with 'confirm-action' links, it is
        also acceptable to provide the token as a query string parameter,
        if there is no POST body.
        """
        # handle query string token if there are no POST parameters
        # this is needed for the 'confirm-action' JavaScript module
        if not self.POST \
                and len(self.GET.getall(anti_csrf.TOKEN_FIELD_NAME)) == 1:
            token = self.GET.getone(anti_csrf.TOKEN_FIELD_NAME)
            del self.GET[anti_csrf.TOKEN_FIELD_NAME]
            return token
        post_tokens = self.POST.getall(anti_csrf.TOKEN_FIELD_NAME)
        if not post_tokens or len(post_tokens) != 1:
            return None
        token = post_tokens[0]
        # drop token from request so it doesn't populate resource extras
        del self.POST[anti_csrf.TOKEN_FIELD_NAME]
        return token

    def get_cookie_token(self):
        """Retrieve the token expected by the server.

           This will be retrieved from the 'token' cookie
           """
        if anti_csrf.TOKEN_FIELD_NAME in self.cookies:
            log.debug("Obtaining token from cookie")
            return self.cookies.get(anti_csrf.TOKEN_FIELD_NAME)
        else:
            return None

    def check_token(self):
        log.debug("Checking token matches Token %s, cookie_token: %s",
                  self.token, self.get_cookie_token())
        return self.token is not None and self.token == self.get_cookie_token()


class CSRFMiddleware(object):

    def __init__(self, app, config):
        self.app = app
        self.domain = config['ckanext.security.domain']

    def __call__(self, environ, start_response):
        request = Request(environ)
        self.session = environ['beaker.session']
        self.session.save()
        if self.is_valid(request):
            resp = request.get_response(self.app)
        else:
            resp = HTTPForbidden(CSRF_ERR)
            return resp(environ, start_response)
        if 'text/html' in resp.headers.get('Content-type', ''):
            token = anti_csrf.get_response_token(request, resp)

            new_response = anti_csrf.apply_token(resp.unicode_body, token)
            resp.unicode_body = new_response
            return resp(environ, start_response)

        else:
            response_value = resp(environ, start_response)
            return response_value

    def is_valid(self, request):
        return request.is_safe() or self.unsafe_request_is_valid(request)

    def unsafe_request_is_valid(self, request):
        return request.is_secure() and request.good_referer(self.domain) and \
            request.good_origin(self.domain) and request.check_token()
