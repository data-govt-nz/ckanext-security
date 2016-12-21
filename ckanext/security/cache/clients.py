from ckan.common import config

import pylibmc


class MemcachedClient(object):
    prefix = ''

    def __init__(self):
        url = config['ckanext.security.memcached']
        conf = {"binary": True, "behaviors": {"tcp_nodelay": True, "ketama": True}}
        self.cli = pylibmc.Client([url], **conf)

    def get(self, key):
        return self.cli.get(self.prefix + key)

    def set(self, key, value):
        return self.cli.set(self.prefix + key, value)

    def delete(self, key):
        return self.cli.delete(self.prefix + key)


class MemcachedCSRFClient(MemcachedClient):
    prefix = 'sec_csrf_'


class MemcachedThrottleClient(MemcachedClient):
    pefix = 'sec_throttle_'
