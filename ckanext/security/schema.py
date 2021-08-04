# encoding: utf-8

import six

from ckan.lib.navl.validators import ignore_missing, not_empty, ignore
from ckan.logic.validators import (
    name_validator, user_name_validator, user_password_not_empty,
    user_passwords_match, ignore_not_sysadmin, user_about_validator,
    user_both_passwords_entered
)
from ckanext.security import validators

# The main purpose of this file is to modify CKAN's user-related schemas, and
# to replace the default password validators everywhere. We are also replacing
# the username validators for endpoints where username changes user to be
# allowed.


def default_user_schema():
    schema = {
        'id': [ignore_missing, six.text_type],
        'name': [not_empty, name_validator, user_name_validator,
                 six.text_type],
        'fullname': [ignore_missing, six.text_type],
        'password': [validators.user_password_validator,
                     user_password_not_empty,
                     ignore_missing, six.text_type],
        'password_hash': [ignore_missing, ignore_not_sysadmin,
                          six.text_type],
        'email': [not_empty, six.text_type],
        'about': [ignore_missing, user_about_validator, six.text_type],
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

    schema['password1'] = [six.text_type, user_both_passwords_entered,
                           validators.user_password_validator,
                           user_passwords_match]
    schema['password2'] = [six.text_type]

    return schema


def user_edit_form_schema():
    schema = default_user_schema()

    schema['password'] = [ignore_missing]
    schema['password1'] = [ignore_missing, six.text_type,
                           validators.user_password_validator,
                           user_passwords_match]
    schema['password2'] = [ignore_missing, six.text_type]

    return schema


def default_update_user_schema():
    schema = default_user_schema()

    schema['name'] = [ignore_missing, name_validator, user_name_validator,
                      six.text_type]
    schema['password'] = [validators.user_password_validator,
                          ignore_missing, six.text_type]

    return schema
