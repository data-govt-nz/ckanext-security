from ckan import model
from ckan.model import DomainObject
from ckan.model.meta import metadata,  mapper, Session
from sqlalchemy import Table, Column, ForeignKey, Index, types
from sqlalchemy.orm import relation
import sys

user_security_totp = None


def db_setup():
    if user_security_totp is None:
        define_security_tables()

    if not model.package_table.exists():
        print("Exiting: can not migrate security model if the database does not exit yet")
        sys.exit(1)
        return

    if not user_security_totp.exists():
        user_security_totp.create()
        print("Created security TOTP table")
    else:
        print("Security TOTP table already exists -- skipping")


def define_security_tables():
    global user_security_totp

    user_security_totp = Table('user_security_totp', metadata,
                               Column('id', types.Integer, primary_key=True),
                               Column('user_id', types.UnicodeText, default=u''),
                               Column('secret', types.UnicodeText, default=u''),
                               Column('last_successful_challenge', types.UnicodeText, default=u''))

    mapper(
        SecurityTOTP,
        user_security_totp
    )

#     TODO add constraint so that when a user is dropped, the security totp is dropped


class SecurityTOTP(DomainObject):
    def __repr__(self):
        return '<SecurityTOTP user_id=%s last_successful_challenge=%s >'\
            .format(self.user_id, self.last_successful_challenge)

    def __str__(self):
        return self.__repr__().encode('ascii', 'ignore')
