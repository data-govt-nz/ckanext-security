import redis
from ckan.common import config

class RedisClient(object):
    prefix = ''

    def __init__(self):
        host = config['ckanext.security.redis.host']
        port = config['ckanext.security.redis.port']
        db = config['ckanext.security.redis.db']
        pwd = config['ckanext.security.redis.password'] \
            if 'ckanext.security.redis.password' in config \
            else None
        self.client = redis.StrictRedis(host=host, port=port, db=db, password=pwd)

    def get(self, key):
        return self.client.get(self.prefix + key)

    def set(self, key, value):
        return self.client.set(self.prefix + key, value)

    def delete(self, key):
        return self.client.delete(self.prefix + key)

class ThrottleClient(RedisClient):
    prefix = 'security_throttle_'
