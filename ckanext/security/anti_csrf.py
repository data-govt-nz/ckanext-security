"""Provides a self-contained filter to prevent Cross-Site Request Forgery,
based on the Double Submit Cookie pattern,
www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookie

The filter can be enabled simply by invoking 'intercept_csrf()'.
"""
import ckan.lib.base as base
import re
from re import DOTALL, IGNORECASE, MULTILINE
from logging import getLogger
from ckan.common import request, response

LOG = getLogger(__name__)

RAW_RENDER = base.render
RAW_RENDER_JINJA = base.render_jinja2
RAW_BEFORE = base.BaseController.__before__

""" Used as the cookie name and input field name.
"""
TOKEN_FIELD_NAME = 'token'
""" Used to rotate the token cookie periodically.
If the freshness cookie doesn't appear, the token cookie is still OK,
but we'll set a new one for next time.
"""
TOKEN_FRESHNESS_COOKIE_NAME = 'token-fresh'

# We need to edit confirm-action links, which get intercepted by JavaScript,
#regardless of which order their 'data-module' and 'href' attributes appear.
CONFIRM_LINK = re.compile(r'(<a [^>]*data-module=["\']confirm-action["\'][^>]*href=["\'][^"\'?]+)(["\'])', IGNORECASE | MULTILINE)
CONFIRM_LINK_REVERSED = re.compile(r'(<a [^>]*href=["\'][^"\'?]+)(["\'][^>]*data-module=["\']confirm-action["\'])', IGNORECASE | MULTILINE)

"""
This will match a POST form that has whitespace after the opening tag (which all existing forms do).
Once we have injected a token immediately after the opening tag,
it won't match any more, which avoids redundant injection.
"""
POST_FORM = re.compile(r'(<form [^>]*method=["\']post["\'][^>]*>)([^<]*\s<)', IGNORECASE | MULTILINE)

"""The format of the token HTML field.
"""
HEX_PATTERN=re.compile(r'^[0-9a-z]+$')
TOKEN_PATTERN = r'<input type="hidden" name="' + TOKEN_FIELD_NAME + '" value="{token}"/>'
TOKEN_SEARCH_PATTERN = re.compile(TOKEN_PATTERN.format(token=r'([0-9a-f]+)'))
API_URL = re.compile(r'^/api\b.*')

def is_logged_in():
    return True

""" Rewrite HTML to insert tokens if applicable.
"""

def anti_csrf_render_jinja2(template_name, extra_vars=None):
    html = apply_token(RAW_RENDER_JINJA(template_name, extra_vars))
    return html

def apply_token(html):
    if not is_logged_in() or not POST_FORM.search(html):
        return html

    token_match = TOKEN_SEARCH_PATTERN.search(html)
    if token_match:
        token = token_match.group(1)
    else:
        token = get_response_token()

    def insert_form_token(form_match):
        return form_match.group(1) + TOKEN_PATTERN.format(token=token) + form_match.group(2)

    def insert_link_token(link_match):
        return link_match.group(1) + '?' + TOKEN_FIELD_NAME + '=' + token + link_match.group(2)

    return CONFIRM_LINK_REVERSED.sub(insert_link_token, CONFIRM_LINK.sub(insert_link_token, POST_FORM.sub(insert_form_token, html)))

def get_cookie_token():
    """Retrieve the token expected by the server.

    This will be retrieved from the 'token' cookie, if it exists.
    If not, an error will occur.
    """
    if request.cookies.has_key(TOKEN_FIELD_NAME):
        LOG.debug("Obtaining token from cookie")
        token = request.cookies.get(TOKEN_FIELD_NAME)
    if token is None or token.strip() == "":
        csrf_fail("CSRF token is blank")

    return token

def get_response_token():
    """Retrieve the token to be injected into pages.

    This will be retrieved from the 'token' cookie, if it exists and is fresh.
    If not, a new token will be generated and a new cookie set.
    """
    # ensure that the same token is used when a page is assembled from pieces
    if request.environ['webob.adhoc_attrs'].has_key('response_token'):
        LOG.debug("Reusing response token from request attributes")
        token = request.response_token
    elif request.cookies.has_key(TOKEN_FIELD_NAME) and request.cookies.has_key(TOKEN_FRESHNESS_COOKIE_NAME):
        LOG.debug("Obtaining token from cookie")
        token = request.cookies.get(TOKEN_FIELD_NAME)
        if not HEX_PATTERN.match(token):
            LOG.debug("Invalid cookie token; making new token cookie")
            token = create_response_token()
        request.response_token = token
    else:
        LOG.debug("No fresh token found; making new token cookie")
        token = create_response_token()
        request.response_token = token

    return token

def create_response_token():
    import binascii, os
    token = binascii.hexlify(os.urandom(32))
    response.set_cookie(TOKEN_FIELD_NAME, token, secure=True, httponly=True)
    response.set_cookie(TOKEN_FRESHNESS_COOKIE_NAME, '1', max_age=600, secure=True, httponly=True)
    return token

# Check token on applicable requests

def is_request_exempt():
    return not is_logged_in() or API_URL.match(request.path) or request.method in {'GET', 'HEAD', 'OPTIONS'}

def anti_csrf_before(obj, action, **params):
    if not is_request_exempt() and get_cookie_token() != get_post_token():
        csrf_fail("Could not match session token with form token")

    RAW_BEFORE(obj, action)

def csrf_fail(message):
    from flask import abort
    LOG.error(message)
    abort(403, "Your form submission could not be validated")

def get_post_token():
    """Retrieve the token provided by the client.

    This is normally a single 'token' parameter in the POST body.
    However, for compatibility with 'confirm-action' links,
    it is also acceptable to provide the token as a query string parameter,
    if it is the *only* parameter of either kind.
    """
    if request.environ['webob.adhoc_attrs'].has_key(TOKEN_FIELD_NAME):
        return request.token

    # handle query string token if there are no other parameters
    # this is needed for the 'confirm-action' JavaScript module
    if not request.POST and len(request.GET) == 1 and len(request.GET.getall(TOKEN_FIELD_NAME)) == 1:
        request.token = request.GET.getone(TOKEN_FIELD_NAME)
        del request.GET[TOKEN_FIELD_NAME]
        return request.token

    postTokens = request.POST.getall(TOKEN_FIELD_NAME)
    if not postTokens:
        csrf_fail("Missing CSRF token in form submission")
    elif len(postTokens) > 1:
        csrf_fail("More than one CSRF token in form submission")
    else:
        request.token = postTokens[0]

    # drop token from request so it doesn't populate resource extras
    del request.POST[TOKEN_FIELD_NAME]

    return request.token

def intercept_csrf():
    base.render_jinja2 = anti_csrf_render_jinja2
    base.BaseController.__before__ = anti_csrf_before
