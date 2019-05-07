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

    def good_referer(self, domain):
        "Returns true if the referrer is https and matching the host"
        if not self.referer:
            return False
        else:
            match = "https://{}".format(domain)
            return self.referer.startswith(match)

    def good_origin(self, domain):
        """
        checks if the origin header is present and matches the header"
        :param domain: string: the expected origin domain
        :return: boolean: true if the origin header is present and matches the expected domain
        """
        origin = self.headers.get('origin', None)
        if not origin:
            log.warning("Potentially unsafe CSRF request is missing the origin header")
            return True
        else:
            match = "https://{}".format(domain)
            return origin.startswith(match)

    def _get_post_token(self):
        """Retrieve the token provided by the client. Or return None if not present

            This is normally a single 'token' parameter in the POST body.
            However, for compatibility with 'confirm-action' links,
            it is also acceptable to provide the token as a query string parameter,
            if there is no POST body.
        """
        # handle query string token if there are no POST parameters
        # this is needed for the 'confirm-action' JavaScript module
        if not self.POST and len(self.GET.getall(anti_csrf.TOKEN_FIELD_NAME)) == 1:
            token = self.GET.getone(anti_csrf.TOKEN_FIELD_NAME)
            del self.GET[anti_csrf.TOKEN_FIELD_NAME]
            return token
        post_tokens = self.POST.getall(anti_csrf.TOKEN_FIELD_NAME)
        if not post_tokens or len(post_tokens) != 1:
            return None
        token = post_tokens[0]
        log.error("GOT TOKEN {}".format(token))
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
        log.error(" Token {}, cookie_token: {}".format(self.token, self.get_cookie_token()))
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
        if 'text/html' in resp.headers.get('Content-type', ''):
            token = anti_csrf.get_response_token(request, resp)
            log.error("Generated a token for the response {}".format(token))

            response_value = resp(environ, start_response)
            return [anti_csrf.apply_token(response_value[0], token)]
        else:
            response_value = resp(environ, start_response)
            return response_value

    def is_valid(self, request):
        log.error("IS _SAFE ? {}".format(request.is_safe()))
        if not request.is_safe():
            log.error("Unsafe req is valid ? {}".format(self.unsafe_request_is_valid(request)))
            log.error('===================================')
        return request.is_safe() or self.unsafe_request_is_valid(request)

    def unsafe_request_is_valid(self, request):
        log.error("is_secure: {}".format(request.is_secure()))
        log.error("good_referer: {}".format(request.good_referer(self.domain)))
        log.error("good_origin: {}".format(request.good_origin(self.domain)))
        log.error("check_token: {}".format(request.check_token()))
        log.error('===================================')
        return request.is_secure() and request.good_referer(self.domain) and \
               request.good_origin(self.domain) and request.check_token()
