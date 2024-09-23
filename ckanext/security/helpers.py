from ckan.plugins.toolkit import asbool, config


def security_enable_totp():
    return asbool(config.get('ckanext.security.enable_totp', True))


def lockout_time():
    lockout = int(config.get('ckanext.security.lockout_time', 60))

    if lockout >= 60:
        time_in_minutes = lockout//60
        alert = f" You failed 3 atempts to login and you have been locked out for {time_in_minutes} minutes. Try again later."
        return alert
    else:
        alert = f"You failed 3 atempts to login and you have been locked out for {lockout} seconds. Try again later."
        return alert
