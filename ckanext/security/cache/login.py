import json
import logging
import time

from ckan.common import config

from ckanext.security.mailer import notify_lockout
from ckanext.security.cache.clients import ThrottleClient


log = logging.getLogger(__name__)


class LoginThrottle(object):
    login_lock_timeout = int(config.get('ckanext.security.lock_timeout', 60 * 15))
    login_max_count = int(config.get('ckanext.security.login_max_count', 10))
    count = 0

    def __init__(self, user, remote_addr):
        self.request_time = time.time()
        self.user = user
        self.cli = ThrottleClient()
        self.remote_addr = remote_addr

        # Separately caching user name, because str(user) yields an unwieldy
        # repr of the User class.
        self.user_name = str(user) if user is None else user.name

    def _check_count(self):
        return self.count >= self.login_max_count

    def _check_time(self, last_attempt):
        return self.request_time - float(last_attempt) < self.login_lock_timeout

    def get(self):
        value = self.cli.get(self.remote_addr)
        if value is not None:
            return json.loads(value)
        return {}

    def reset(self):
        value = self.get()
        if self.user_name in value:
            del value[self.user_name]
        self.cli.set(self.remote_addr, json.dumps(value))

    def increment(self):
        value = self.get()
        # An email will be sent once the count has reached login_max_count, so we
        # will only increment this counter until login_max_count + 1. Otherwise,
        # the user would be locked out for another `login_lock_timeout` minutes
        # whenever he/she tries to login again.
        if self.count < self.login_max_count + 1:
            value.update({self.user_name: "%s:%s" % (self.count + 1, self.request_time)})
            self.cli.set(self.remote_addr, json.dumps(value))

    def needs_lockout(self, cache_value):
        count, last_attempt = cache_value.split(':')
        self.count = int(count) if self._check_time(last_attempt) else 0
        if self._check_count():
            if self.user is not None and self.count == self.login_max_count:
                log.info("%s locked out by brute force protection" % self.user.name)
                try:
                    notify_lockout(self.user, self.remote_addr)
                    log.debug("Lockout notification for user %s sent" % self.user.name)
                except Exception as exc:
                    msg = "Sending lockout notification for %s failed"
                    log.exception(msg % self.user.name, exc_info=exc)
            return False

    def check_attempts(self):
        cached = self.get().get(self.user_name, None)
        if cached is not None:
            return self.needs_lockout(cached)
