# CKANEXT-SECURITY

## What am I?
A CKAN extension to hold various security improvements for CKAN, including:

* Stronger password reset tokens
* Brute force protection
* Removed ability to change usernames after signup
* Server-side session storage
* Session invalidation on logout
* Stronger password validators (NZISM compatible)
* When users try to reset a password for an email address, CKAN will no longer
disclose whether or not that email address exists in the DB
* Two Factor Authentication is enforced for all users
* Preventing upload/linking of certain file types for resources

**Please note**:
* This extension has been used and tested against CKAN version 2.7.x on git tag 2.5.0 and earlier
* CKAN 2.9.x and Python 3 support was added from git tag 3.0.0
* This extension used to provide CSRF protection (in git tags 2.5.0 and earlier). This is no longer provided, please use [ckanext-csrf-filter](https://github.com/qld-gov-au/ckanext-csrf-filter) instead.
* Support for CKAN versions earlier than 2.9.x is now dropped from git tag 4.0.0

### Reset tokens
Reset tokens are generated using `os.urandom(16)` instead of CKAN's default
`uuid.uuid4().hex[:10]`.

### Brute force protection
Users attempting to log in more than `ckanext.security.login_max_count` times
within `ckanext.security.lock_timeout` seconds will be temporarily locked out.

By default, this means that after 10 unsuccessful login attempts from the same IP address within 15 minutes
the login will be disabled for another 15 minutes.

Failed two factor authentication code attempts are included in the count of unsuccessful login attempts. For example, five failed username and password attempts and then five failed 2fa codes will trigger the brute force lockout.

Setting `ckanext.security.brute_force_key` to `user_name` will ignore the IP address so that unsuccessful login attempts will be detected
based on user_name only. This provides greater security against attackers that can vary their IP address at the cost of the legitimate user getting locked out as well.

A notification email will be sent to locked out users.
The email footer content can be overridden by providing a path to a file that will replace the content in `templates/security/emails/lockout_footer.txt` in this module.
The path can be provided via the `ckanext.security.brute_force_footer_path` config option.

Sysadmins may use the `security_throttle_user_show` or `security_throttle_address_show` actions to query the brute force lockout status for a username or IP address. The `security_throttle_user_reset` and `security_throttle_address_reset` actions may be used to clear a brute force lockout status before the configured timeout.

Lockouts are removed automatically when a user's password is reset or their account is modified.

### Two Factor Authentication enforcement
Users are required to use Two Factor Authentication (2fa). This feature adds a two step login flow, where the user adds their username and password first, then their 2fa code after. They are presented with a QR code to configure an authentication app on first login, then just an input for the one-time code on subsequent logins.

A configuration interface is provided so that the user may reset their 2fa secret if needed, and sysadmins may use this facility to reset a locked out user.

A cli command is also provided for resetting a user's 2fa secret from the commandline on the server:
```shell
ckan -c /PATH_TO_YOUR_INI_FILE/FILENAME.ini security reset_totp <username>
```

### Resource upload/linking file type blacklist
This feature prevents uploads for a configurable set of file types.
Users are shown an error message when creating or updating resources if they upload a file that is detected as matching one of the blacklisted types.

**NOTE**: `.exe` files or those with the detected mime type `application/x-dosexec` are blocked by default as part of this feature.

**File type detection**:

This is performed using the `mimetypes` and `python-magic` libraries.
* `mimetypes` makes a guess at the mime type based on the extension in the filename
* `python-magic` makes a guess the mime type based on parsing the file contents

**Example configuration**:
* `ckanext.security.upload_blacklist: ['.png', 'image/jpg']` blocks any files with the given extensions or mime types.
* `ckanext.security.extended_upload_mimetypes: { 'image/jpeg': '.jpg' }` adds mimetypes to extension mappings to the `mimetypes` python library. This improves file type checking in instances where the filename has no extension or the extension is not correct for the file type.

**Debugging**:

If you are trying to configure a file type and it doesn't seem to be getting blocked (mostly this could happen if the file had the extension removed or changed),
you can try viewing the ckan logs for a line like this:

`INFO  [ckanext.security.resource_upload_validator] Detected extensions/mimetypes: ['application/some_mime_type']`

If you were expecting the file to match `'.ext'` in your blacklist, you can add a mapping from the detected mime type to the extension using the `extended_upload_mimetypes` config:

`ckanext.security.extended_upload_mimetypes: { 'application/some_mime_type': '.ext' }`

You can also achieve this by adding the detected mime type to your blacklist directly:

`ckanext.security.upload_blacklist: ['application/some_mime_type']`

**Limitations**:

Links are only checked based on the extension in the url, we do not request the file at the linked url to infer the mime type.

## Requirements
* The server-side session storage requires the session middleware in CKAN core to be moved near the end of the middleware stack. An example changeset (relevant to CKAN 2.9.3) for this is provided in [ckanext-security.patch](ckanext-security.patch). The installed CKAN core codebase will need to have this patch applied (or similar changes made if not using 2.9.3).
* A running Redis instance to store brute force protection tokens configured with a maxmemory and maxmemory-policy=lru so it overwrites the least recently used item rather than running out of space. This instance should be a different instance from the one used for Harvest items to avoid data loss. [Redis LRU-Cache documentation](https://redis.io/topics/lru-cache).

### Changes to `who.ini`
You will need at least the following setting in your `who.ini`

```ini
[plugin:use_beaker]
use = repoze.who.plugins.use_beaker:make_plugin
key_name = ckan_session
delete_on_logout = True

[plugin:friendlyform]
# <your other settings here>
rememberer_name = use_beaker

[identifiers]
plugins =
    friendlyform;browser
    use_beaker

[authenticators]
plugins =
    ckanext.security.authenticator:CKANLoginThrottle
    ckanext.security.authenticator:BeakerRedisAuth
```

### Changes to CKAN config
For better security, make sure you harden your session configuration (in your
  ckan config file). See for example the settings below.

```ini
[app:main]
# <your other settings here>
beaker.session.key = ckan_session
# Your session secret should be a long, random and secret string!
beaker.session.secret = beaker-secret
beaker.session.data_serializer = json
beaker.session.httponly = true
beaker.session.secure = true
beaker.session.timeout = 3600
beaker.session.save_accessed_time = true
beaker.session.type = ext:redis
beaker.session.url = redis://127.0.0.1:6379
beaker.session.cookie_expires = true
# Your domain should show here.
beaker.session.cookie_domain = 192.168.232.65
```

### ckanext-security configuration options
```ini
## Security
ckanext.security.domain = 192.168.232.65          # Cookie domain

ckanext.security.redis.host = 127.0.0.1
ckanext.security.redis.port = 6379
ckanext.security.redis.db = 1                     # ckan uses db 0
ckanext.security.redis.password = StrongPassword  # optional password for Redis

# 15 minute timeout with 10 attempts
ckanext.security.lock_timeout = 900               # Login throttling lock period
ckanext.security.login_max_count = 10             # Login throttling attempt limit
ckanext.security.brute_force_key = user_name      # Detect brute force attempts by username rather than IP address

# If using 2.7.7 or recent patches of 2.8, the password reset behaviour has been fixed in CKAN core
# (no longer discloses info about non-existent accounts) and the way this plugin overrides the password
# reset may be broken due to permission restrictions on user lookups,
# You can disable the fix in this plugin by:
ckanext.security.disable_password_reset_override = true

# Two factor authentication is enabled for all users by default
# optional configuration to disable 2fa
ckanext.security.enable_totp = true         # set to false to disable 2fa 

# Provide a help page to allow 2fa users to contact support or get more information
# Shows up as 'Need help?' on the 2fa entry form beside the submit button. Does not display a link if none provided
ckanext.security.mfa_help_link = https://data.govt.nz/catalogue-guide/releasing-data-on-data-govt-nz/how-do-i-set-up-two-factor-authentication/
```

## How to install?
You can use `pip` to install this plugin into your virtual environment:

```shell
pip install -e git+https://github.com/data-govt-nz/ckanext-security.git#egg=ckanext-security
pip install -r ckanext-security/requirements.txt # or requirements-py2.txt if running Python 2.7 still
```

You need to migrate the database in order to enable the Two Factor Auth. This command is idempotent, it will not modify the database if run again once the table exists.
```shell
ckan -c /PATH_TO_YOUR_INI_FILE/FILENAME.ini security migrate
```

Finally, add `security` to `ckan.plugins` in your config file.

## Possible problems

- If you see a `ValueError: No Beaker session (beaker.session) in environment` then you have not installed the patch to CKAN correctly.
