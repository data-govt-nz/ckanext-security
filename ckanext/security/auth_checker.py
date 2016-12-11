import os
import ConfigParser

from sqlalchemy import create_engine

from ckan.model import User, init_model


CONF = os.environ.get('CKAN_CONFIG') or os.environ.get('CKAN_INI')
config = ConfigParser.ConfigParser()
config.read(CONF)
DBURL = config.get('app:main', 'sqlalchemy.url')


def user_exists(name):
    engine = create_engine(DBURL, client_encoding='utf8')
    init_model(engine)
    user = User.by_name(unicode(name))
    return bool(user and user.is_active())
