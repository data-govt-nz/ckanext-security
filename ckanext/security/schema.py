from ckan.lib.navl.validators import ignore_missing, not_empty, ignore, not_missing
from ckan.logic.validators import name_validator, user_name_validator, \
    user_password_not_empty, user_passwords_match, ignore_not_sysadmin, \
    ignore_not_group_admin, ignore_not_package_admin, user_about_validator
from ckan.logic import schema as ckan_schema

from ckanext.security import validators


def default_user_schema():
    schema = {
        'id': [ignore_missing, unicode],
        'name': [not_empty, name_validator, user_name_validator, unicode],
        'fullname': [ignore_missing, unicode],
        'password': [validators.user_password_validator, user_password_not_empty,
                     ignore_missing, unicode],
        'password_hash': [ignore_missing, ignore_not_sysadmin, unicode],
        'email': [not_empty, unicode],
        'about': [ignore_missing, user_about_validator, unicode],
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

    schema['password1'] = [unicode, user_both_passwords_entered,
                           validators.user_password_validator, user_passwords_match]
    schema['password2'] = [unicode]

    return schema


def user_edit_form_schema():
    schema = default_user_schema()

    schema['password'] = [ignore_missing]
    schema['password1'] = [ignore_missing, unicode, validators.user_password_validator,
                           user_passwords_match]
    schema['password2'] = [ignore_missing, unicode]

    return schema


def default_update_user_schema():
    schema = default_user_schema()

    schema['name'] = [ignore_missing, name_validator, user_name_validator,
                      unicode]
    schema['password'] = [validators.user_password_validator, ignore_missing, unicode]

    return schema
