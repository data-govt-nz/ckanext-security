# encoding: utf-8

import six

from ckan.lib.navl.validators import ignore_missing, not_empty, ignore
from ckan.logic.validators import (
    name_validator, user_name_validator, user_password_not_empty,
    user_passwords_match, ignore_not_sysadmin, user_about_validator,
    user_both_passwords_entered
)
from ckanext.security.validators import (
    user_password_validator, old_username_validator, ensure_str
)

# The main purpose of this file is to modify CKAN's user-related schemas, and
# to replace the default password validators everywhere. We are also replacing
# the username validators for endpoints where username changes user to be
# allowed.


def default_user_schema():
    schema = {
        'id': [ignore_missing, ensure_str],
        'name': [not_empty, name_validator, user_name_validator,
                 ensure_str],
        'fullname': [ignore_missing, ensure_str],
        'password': [user_password_validator,
                     user_password_not_empty,
                     ignore_missing, ensure_str],
        'password_hash': [ignore_missing, ignore_not_sysadmin,
                          ensure_str],
        'email': [not_empty, ensure_str],
        'about': [ignore_missing, user_about_validator, ensure_str],
        'created': [ignore],
        'openid': [ignore_missing],
        'sysadmin': [ignore_missing, ignore_not_sysadmin],
        'apikey': [ignore],
        'reset_key': [ignore],
        'activity_streams_email_notifications': [ignore_missing],
        'state': [ignore_missing],
    }
    return schema


def user_new_form_schema():
    schema = default_user_schema()

    schema['password1'] = [ensure_str, user_both_passwords_entered,
                           user_password_validator,
                           user_passwords_match]
    schema['password2'] = [ensure_str]

    return schema


def user_edit_form_schema():
    schema = default_user_schema()

    schema['name'] += [old_username_validator]
    schema['password'] = [ignore_missing]
    schema['password1'] = [ignore_missing, ensure_str,
                           user_password_validator,
                           user_passwords_match]
    schema['password2'] = [ignore_missing, ensure_str]

    return schema


def default_update_user_schema():
    schema = default_user_schema()

    schema['name'] = [ignore_missing, name_validator, user_name_validator,
                      ensure_str]
    schema['password'] = [user_password_validator,
                          ignore_missing, ensure_str]

    return schema
