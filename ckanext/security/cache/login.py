from builtins import object
import json
import logging
import time

from ckan.common import config
from ckanext.security.mailer import notify_lockout
from ckanext.security.cache.clients import ThrottleClient


log = logging.getLogger(__name__)

default_lockout_timeout = 60 * 15
default_max_login_attempts = 10


def lockout_timeout():
    return int(config.get('ckanext.security.lock_timeout',
                          default_lockout_timeout))


def max_login_attempts():
    return int(config.get('ckanext.security.login_max_count',
                          default_max_login_attempts))


class LoginThrottle(object):
    login_lock_timeout = lockout_timeout()
    login_max_count = max_login_attempts()
    count = 0
    last_failed_attempt = 0

    def __init__(self, user, key):
        self.request_time = time.time()
        self.user = user
        self.cli = ThrottleClient()
        self.key = key

    def _check_count(self):
        return self.count >= self.login_max_count

    def _check_time_since_last_attempt(self, last_attempt):
        return self.request_time - float(last_attempt) < \
            self.login_lock_timeout

    def get(self):
        value = self.cli.get(self.key)
        if value is not None:
            return json.loads(value)
        return {}

    def reset(self):
        value = self.get()
        value['count'] = 0
        self.cli.set(self.key, json.dumps(value))

    def increment(self):
        value = self.get()
        # An email will be sent once the count has reached login_max_count,
        # so we will only increment this counter until login_max_count + 1.
        # Otherwise, the user would be locked out for another
        # `login_lock_timeout` minutes whenever he/she tries to login again.
        if self.count < self.login_max_count + 1:
            value.update({
                'count': self.count + 1,
                'last_failed_attempt': self.request_time,
            })
            self.cli.set(self.key, json.dumps(value))

    def needs_lockout(self):
        if self.user is not None and self.count == self.login_max_count:
            log.info("%s locked out by brute force protection",
                     self.user.name)
            try:
                notify_lockout(self.user, self.login_lock_timeout)
                log.debug("Lockout notification for user %s sent",
                          self.user.name)
            except Exception as exc:
                msg = "Sending lockout notification for %s failed"
                log.exception(msg % self.user.name, exc_info=exc)
        return False

    def check_attempts(self):
        value = self.get()
        in_possible_lockout_window = self._check_time_since_last_attempt(
            value.get('last_failed_attempt', 0))
        self.count = value.get('count', 0) if in_possible_lockout_window else 0
        if self._check_count():
            return self.needs_lockout()

    def is_locked(self):
        if self.check_attempts() is False:
            # Increment so we only send an email the first time around
            self.increment()
            return True
        return False
