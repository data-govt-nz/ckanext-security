# CKANEXT-SECURITY

## What am I?
A CKAN extension to hold various security improvements for CKAN, including:

* Stronger password reset tokens
* Brute force protection
* Cookie-based CSRF protection for requests
* Removed ability to change usernames after signup
* Server-side session storage
* Session invalidation on logout
* Stronger password validators (NZISM compatible)
* When users try to reset a password for an email address, CKAN will no longer
disclose whether or not that email address exists in the DB.

### Reset tokens
Reset tokens are generated using `os.urandom(16)` instead of CKAN's default
`uuid.uuid4().hex[:10]`.

### Brute force protection
Users attempting to log in more than `ckanext.security.login_max_count` times
within `ckanext.security.lock_timeout` seconds from a single IP address will be
temporarily locked out.

By default, this means that after 10 unsuccessful login attempts within 15 minutes
the login will be disabled for another 15 minutes.

A notification email will be sent to locked out users.


## Requirements

* Session- and CSRFMiddleware need to be placed at the bottom of the middleware
stack. This requires to patch `ckan.config.middleware.pylons_app`. The patch is
currently available in the data.govt.nz [CKAN repository](https://github.com/data-govt-nz/ckan/) on the `dia` branch,
or [commit `74f78865`](https://github.com/data-govt-nz/ckan/commit/74f78865b8825c91d1dfe6b189228f4b975610a3) for cherry-pick.
* A running memcached instance and `libmemcached-dev`.

### Changes to `who.ini`
You will need at least the following setting ins your `who.ini`

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
    ckanext.security.authenticator:BeakerMemcachedAuth
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
beaker.session.type = ext:memcached
beaker.session.url = 127.0.0.1:11211
beaker.session.memcache_module = pylibmc
beaker.session.cookie_expires = true
# Your domain should show here.
beaker.session.cookie_domain = 192.168.232.65
```

### ckanext-security configuration options
```ini
## Security
ckanext.security.memcached = 127.0.0.1:11211  # Memcached URL
ckanext.security.domain = 192.168.232.65      # Cookie domain

# 15 minute timeout with 10 attempts
ckanext.security.lock_timeout = 900           # Login throttling lock period
ckanext.security.login_max_count = 10         # Login throttling attempt limit
```

## How to install?
You can use `pip` to install this plugin into your virtual environment:

```shell
pip install --process-dependency-links -e 'https://github.com/data-govt-nz/ckanext-security.git#egg=ckanext-security==0.0.1'
```
*NOTE: The ``--process-dependency-links` flag has officially been deprecated, but
has not been removed from pip, because it is the currently the only
setuptools-supported way for specifying private repo dependencies*

Then modify your CKAN config to point the extension at your memcached instance:
```ini
ckanext.security.memcached = 127.0.0.1:11211
```

Finally, add `security` to `ckan.plugins` in your config file.
