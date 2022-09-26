'''
Action functions, all sysadmin-only
'''

from ckan import authz, model
from ckan.logic import auth as logic_auth
from ckan.plugins.toolkit import _, asbool, config, \
    auth_allow_anonymous_access, chained_auth_function


def security_throttle_user_reset(context, data_dict):
    return {'success': False}


def security_throttle_address_reset(context, data_dict):
    return {'success': False}


def security_throttle_user_show(context, data_dict):
    return {'success': False}


def security_throttle_address_show(context, data_dict):
    return {'success': False}


def security_reset_totp(context, data_dict):
    return {'success': False}


# User privacy enhancements


@chained_auth_function
def user_list(next_auth, context, data_dict=None):
    """Check whether access to the user list is authorised.
    Restricted to admins if 'ckan.auth.public_user_details' is False.
    """
    if asbool(config.get('ckan.auth.public_user_details', True)) \
            or _requester_is_admin(context):
        return next_auth(context, data_dict)
    else:
        return {'success': False}


@chained_auth_function
@auth_allow_anonymous_access
def user_show(next_auth, context, data_dict):
    """Check whether access to individual user details is authorised.
    Restricted to admins or self if 'ckan.auth.public_user_details' is False.
    """
    if asbool(config.get('ckan.auth.public_user_details', True)) \
            or _requester_is_admin(context):
        authorized = True
    else:
        requester = context.get('user')
        id = data_dict.get('id', None)
        if id:
            user_obj = model.User.get(id)
        else:
            user_obj = data_dict.get('user_obj', None)
        authorized = user_obj and requester in [user_obj.name, user_obj.id]
    if authorized:
        return next_auth(context, data_dict)

    return {'success': False}


@chained_auth_function
@auth_allow_anonymous_access
def group_show(next_auth, context, data_dict):
    """Check whether access to a group is authorised.
    If it's just the group metadata, this requires no privileges,
    but if user details have been requested and
    'ckan.auth.public_user_details' is False, it requires a group admin.
    """
    if asbool(config.get('ckan.auth.public_user_details', True)):
        authorized = True
    else:
        user = context.get('user')
        group = logic_auth.get_group_object(context, data_dict)
        authorized = (
            group.state == 'active'
            and not asbool(data_dict.get('include_users', False))
            and data_dict.get('object_type', None) != 'user'
        ) or authz.has_user_permission_for_group_or_org(group.id, user, 'update')
    if authorized:
        return next_auth(context, data_dict)
    else:
        return {'success': False,
                'msg': _('User %s not authorized to read group %s') % (user, group.id)}


def _requester_is_admin(context):
    """Check whether the current user has admin privileges in some group
    or organisation.
    This is based on the 'update' privilege; see eg
    ckan.logic.auth.update.group_edit_permissions.
    """
    requester = context.get('user')
    return _has_user_permission_for_some_group(requester, 'admin')


def _has_user_permission_for_some_group(user_name, permission):
    """Check if the user has the given permission for any group.
    """
    user_id = authz.get_user_id_for_username(user_name, allow_none=True)
    if not user_id:
        return False
    roles = authz.get_roles_with_permission(permission)

    if not roles:
        return False
    # get any groups the user has with the needed role
    q = model.Session.query(model.Member) \
        .filter(model.Member.table_name == 'user') \
        .filter(model.Member.state == 'active') \
        .filter(model.Member.capacity.in_(roles)) \
        .filter(model.Member.table_id == user_id)
    group_ids = []
    for row in q.all():
        group_ids.append(row.group_id)
    # if not in any groups has no permissions
    if not group_ids:
        return False

    # see if any of the groups are active
    q = model.Session.query(model.Group) \
        .filter(model.Group.state == 'active') \
        .filter(model.Group.id.in_(group_ids))

    return bool(q.count())
