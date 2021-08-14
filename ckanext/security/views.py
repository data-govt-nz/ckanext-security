# -*- coding: utf-8 -*-

import logging

from ckan.views import user
from ckanext.security import utils
from ckan.lib import helpers
from flask import Blueprint, make_response, request
from functools import wraps
from ckan.plugins import toolkit as tk

log = logging.getLogger(__name__)


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
    return make_response((res_data, status, headers))


@login_required
def configure_mfa(id=None):
    extra_vars = utils.configure_mfa(id)
    return tk.render('security/configure_mfa.html',
                     extra_vars={'c': extra_vars})


@login_required
def new(id=None):
    utils.new(id)
    return helpers.redirect_to('mfa_user.configure_mfa', id=id)


mfa_user.add_url_rule('/api/mfa_login', view_func=login, methods=['POST'])
mfa_user.add_url_rule('/configure_mfa/<id>',
                      view_func=configure_mfa, methods=['GET', 'POST'])
mfa_user.add_url_rule('/configure_mfa/<id>/new',
                      view_func=new, methods=['GET', 'POST'])


def get_blueprints():
    return [mfa_user]
