from ckan.plugins.toolkit import (
    get_action,
    chained_action,
    check_access,
    get_or_bust,
    asint,
    config
)

from ckanext.security.authenticator import (
    get_user_throttle,
    get_address_throttle,
    reset_user_throttle,
    reset_address_throttle,
    reset_totp
)
from ckanext.security.constants import PLUGIN_EXTRAS_BLACKLIST_KEY


def security_throttle_user_reset(context, data_dict):
    """
    Reset throttling information for a user, allowing logins

    address: user name
    """
    check_access('security_throttle_user_reset', context, data_dict)
    user = get_or_bust(data_dict, 'user')
    return reset_user_throttle(user)


def security_throttle_address_reset(context, data_dict):
    """
    Reset throttling information for an address, allowing logins

    address: IP address
    """
    check_access('security_throttle_address_reset', context, data_dict)
    address = get_or_bust(data_dict, 'address')
    return reset_address_throttle(address)


def security_throttle_user_show(context, data_dict):
    """
    Retrieve the throttling information for a user

    user: user name
    """
    check_access('security_throttle_user_show', context, data_dict)
    user = get_or_bust(data_dict, 'user')
    return get_user_throttle(user)


def security_throttle_address_show(context, data_dict):
    """
    Retrieve the throttling information for an IP address

    address: IP address
    """
    check_access('security_throttle_address_show', context, data_dict)
    address = get_or_bust(data_dict, 'address')
    return get_address_throttle(address)


def security_reset_totp(context, data_dict):
    check_access('security_reset_totp', context, data_dict)
    user = get_or_bust(data_dict, 'user')
    return reset_totp(user)


@chained_action
def user_update(up_func, context, data_dict):
    """
    ckanext-security: reset throttling information for updated users
    to allow new login attempts after password reset
    """

    # Save the current password hash
    model = context['model']
    user_id = get_or_bust(data_dict, 'id')
    current_password_hash = model.User.get(user_id).password

    # Call the original user_update function
    rval = up_func(context, data_dict)

    # Reset the security throttle for the user
    get_action('security_throttle_user_reset')(dict(context, ignore_auth=True), {'user': rval['name']})

    # If the password was changed, record it in the blacklist
    updated_stored_user = model.User.get(user_id)
    if current_password_hash != updated_stored_user.password:
        _append_password(context, updated_stored_user)

    return rval


@chained_action
def user_create(up_func, context, data_dict):
    """
    Store the password hash in the blacklist on user creation.
    """

    # Call the original user_update function
    rval = up_func(context, data_dict)

    # Store the password hash in the blacklist
    model = context['model']
    user_id = get_or_bust(rval, 'id')
    updated_stored_user = model.User.get(user_id)
    _append_password(context, updated_stored_user)

    return rval


def _append_password(context, user_obj):
    """
    Append the new password hash to the list of forbidden passwords
    """

    blacklist_item_count = asint(config.get('ckanext.security.blacklist_item_count', 0))
    if blacklist_item_count == 0:
        return  # feature is disabled

    if not user_obj.password:
        return  # this can happen if an user is created with an invite link

    if user_obj.plugin_extras is None:
        user_obj.plugin_extras = {}
    if PLUGIN_EXTRAS_BLACKLIST_KEY not in user_obj.plugin_extras:
        user_obj.plugin_extras[PLUGIN_EXTRAS_BLACKLIST_KEY] = []

    max_appended_elements = int(blacklist_item_count) - 1
    new_list = [user_obj.password] + user_obj.plugin_extras[PLUGIN_EXTRAS_BLACKLIST_KEY][:max_appended_elements]
    user_obj.plugin_extras[PLUGIN_EXTRAS_BLACKLIST_KEY] = new_list

    # user_patch; Own implementation because we need to set the "keep_email" in context for a valid request.
    # CKANs user_update needs an email address to update the user.
    # CKANs user_patch will do user_show without getting the email address, thus failing on the user_update.
    user_dict = get_action('user_show')(dict(context, ignore_auth=True, keep_email=True), {'id': user_obj.id})
    patched = dict(user_dict)
    patched.pop('display_name', None)
    patched.update({'plugin_extras': user_obj.plugin_extras})
    get_action('user_update')(dict(context, ignore_auth=True), patched)
