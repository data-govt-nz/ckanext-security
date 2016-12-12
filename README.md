# CKANEXT-DIA

## What am I?
A CKAN extension to hold various security improvements for CKAN, including:

* Stronger password reset tokens
* Cookie-based CSRF protection for requests
* Removed ability to change usernames after signup
* Server-side session storage
* Session invalidation on logout
* Stronger password validators (NZISM compatible)


## Requirements

* Session- and CSRFMiddleware need to be placed at the bottom of the middleware
stack. This requires to patch `ckan.config.middleware.pylons_app`. The patch is
currently available in the Catalyst CKAN repository on the `catalyst/dia` branch,
or commit `74f78865` for cherry-pick.
* A running memcached instance and `libmemcached-dev`.
* Your `who.ini` file needs the following settings:

```
[plugin:use_beaker]
use = repoze.who.plugins.use_beaker:make_plugin
key_name = ckan_session
delete_on_logout = True

[plugin:friendlyform]
rememberer_name = use_beaker
<your other settings here>

[identifiers]
plugins =
    friendlyform;browser
    use_beaker

[authenticators]
plugins =
    ckan.lib.authenticator:UsernamePasswordAuthenticator
    ckanext.security.plugin:BeakerAuthenticator
```

## How to install?
You can use `pip` to install this plugin into your virtual environment:

```
pip install --process-dependency-links -e 'git+ssh@gitlab.wgtn.cat-it.co.nz/ckan/ckanext-security.git#egg=ckanext-security==0.0.1'
```
*NOTE: The --process-dependency-links has officially been deprecated, but not
removed pip because it is the currently the only setuptools-supported way for
specifying private repo dependencies*

Then modify your CKAN config to point the extension at your memcached instance:
```
ckanext.security.memcached = 127.0.0.1:11211
```

Finally, add `catsec` to `ckan.plugins` in your config file.
