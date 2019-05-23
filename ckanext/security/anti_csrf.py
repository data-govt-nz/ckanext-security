"""Provides a filter to prevent Cross-Site Request Forgery,
based on the Double Submit Cookie pattern,
https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md#double-submit-cookie

This is integrated in the CSRFMiddleware
"""
import ckan.lib.base as base
import re
from re import IGNORECASE, MULTILINE
from logging import getLogger
from ckan.common import request

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
CONFIRM_LINK = re.compile(r'(<a [^>]*data-module=["\']confirm-action["\'][^>]*href=["\']([^"\']+))(["\'])', IGNORECASE | MULTILINE)
CONFIRM_LINK_REVERSED = re.compile(r'(<a [^>]*href=["\']([^"\']+))(["\'][^>]*data-module=["\']confirm-action["\'])', IGNORECASE | MULTILINE)

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
    # auth_tkt does not exist in context..
    # return request.cookies.get("auth_tkt")
    return True

def apply_token(html, token):
    """ Rewrite HTML to insert tokens if applicable.
    """
    if not is_logged_in():
        return html

    token_match = TOKEN_SEARCH_PATTERN.search(html)
    if token_match:
        token = token_match.group(1)

    def insert_form_token(form_match):
        return form_match.group(1) + TOKEN_PATTERN.format(token=token) + form_match.group(2)

    def insert_link_token(link_match):
        if '?' in link_match.group(2):
            separator = '&'
        else:
            separator = '?'
        return link_match.group(1) + separator + TOKEN_FIELD_NAME + '=' + token + link_match.group(3)

    return CONFIRM_LINK_REVERSED.sub(insert_link_token, CONFIRM_LINK.sub(insert_link_token, POST_FORM.sub(insert_form_token, html)))


def get_cookie_token(request):
    """Retrieve the token expected by the server.

    This will be retrieved from the 'token' cookie, if it exists.
    If not, an error will occur.
    """
    token = None
    if request.cookies.has_key(TOKEN_FIELD_NAME):
        LOG.debug("Obtaining token from cookie")
        token = request.cookies.get(TOKEN_FIELD_NAME)
    if token is None or token.strip() == "":
        csrf_fail("CSRF token is blank")
    return token

def get_response_token(request, response):
    """Retrieve the token to be injected into pages.

    This will be retrieved from the 'token' cookie, if it exists and is fresh.
    If not, a new token will be generated and a new cookie set.
    """
    # ensure that the same token is used when a page is assembled from pieces
    if TOKEN_FIELD_NAME in request.cookies and TOKEN_FRESHNESS_COOKIE_NAME in request.cookies:
        LOG.debug("Obtaining token from cookie")
        token = request.cookies.get(TOKEN_FIELD_NAME)
        if not HEX_PATTERN.match(token):
            LOG.debug("Invalid cookie token; making new token cookie")
            token = create_response_token(response)
    else:
        LOG.debug("No fresh token found; making new token cookie")
        token = create_response_token(response)
    return token

def create_response_token(response):
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

def get_post_token(request):
    """Retrieve the token provided by the client.

    This is normally a single 'token' parameter in the POST body.
    However, for compatibility with 'confirm-action' links,
    it is also acceptable to provide the token as a query string parameter,
    if there is no POST body.
    """
    if request.environ['webob.adhoc_attrs'].has_key(TOKEN_FIELD_NAME):
        return request.token

    # handle query string token if there are no POST parameters
    # this is needed for the 'confirm-action' JavaScript module
    if not request.POST and len(request.GET.getall(TOKEN_FIELD_NAME)) == 1:
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

