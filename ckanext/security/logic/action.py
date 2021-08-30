from ckan.plugins.toolkit import (
    get_action,
    chained_action,
    check_access, get_or_bust)
from ckanext.security.authenticator import (
    get_user_throttle,
    get_address_throttle,
    reset_user_throttle,
    reset_address_throttle,
    reset_totp
)


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
    rval = up_func(context, data_dict)
    get_action('security_throttle_user_reset')(
        dict(context, ignore_auth=True), {'user': rval['name']})
    return rval
