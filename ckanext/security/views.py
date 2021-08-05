# -*- coding: utf-8 -*-

from ckan.views import user
from ckanext.security import utils
from flask import Blueprint, make_response
from functools import wraps


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        utils.check_user_and_access()
        return f(*args, **kwargs)
    return decorated_function


mfa_user = Blueprint("mfa_user", __name__)


def login():
    headers = {'Content-Type': 'application/json'}
    (status, res_data) = utils.login()
    make_response((res_data, status, headers))


@login_required
def configure_mfa(id=None):
    return utils.configure_mfa(id)


@login_required
def new(id=None):
    return utils.new(id)


mfa_user.add_url_rule('/api/mfa_login', view_func=login)
mfa_user.add_url_rule('/configure_mfa/<id>', view_func=configure_mfa)
mfa_user.add_url_rule('/configure_mfa/<id>/new', view_func=new)


def get_blueprints():
    return [mfa_user]


# Override user edit form template
user.edit_user_form = u'security/edit_user_form.html'
