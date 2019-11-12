import datetime

from ckan import model
from ckan.model import DomainObject, User
from ckan.model.meta import metadata,  mapper, Session
from sqlalchemy import Table, Column, ForeignKey, Index, types, text
from sqlalchemy.orm import relation
import logging
import pyotp

import sys
log = logging.getLogger(__name__)

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
    if user_security_totp is not None:
        return
    user_security_totp = Table('user_security_totp', metadata,
                               Column('id', types.Integer, primary_key=True),
                               Column('user_id', types.UnicodeText, default=u''),
                               Column('secret', types.UnicodeText, default=u''),
                               Column('last_successful_challenge', types.DateTime, default=u''))

    mapper(
        SecurityTOTP,
        user_security_totp
    )


class ReplayAttackException(Exception):
    """Thrown when we detect an attempted replay attack"""
    pass


class SecurityTOTP(DomainObject):

    @classmethod
    def get_for_user(self, user_name):
        '''Finds a securityTOTP object using the user name'''
        if user_name is None:
            raise ValueError("User name parameter must be suppllied")

        challenger = SecurityTOTP.Session.query(SecurityTOTP)\
            .join(User, User.id == SecurityTOTP.user_id) \
            .filter(User.name == user_name).first()
        return challenger


    def check_code(self, code):
        """ Checks that a one time password is correct against the model
        :raises ReplayAttackException if the code has already been used before, and it is attempted to be used again
        :return boolean true if the code is valid
        """
        totp = pyotp.TOTP(self.secret)
        result = totp.verify(code)
        if result:
            # check for replay attack...
            if self.last_successful_challenge and totp.at(self.last_successful_challenge) == code:
                raise ReplayAttackException("the replay code has already been used")

            self.last_successful_challenge = datetime.datetime.utcnow()
            self.save()
        else:
            log.debug("Failed to verify the totp code")

        return result
    def __repr__(self):
        return '<SecurityTOTP user_id=%s last_successful_challenge=%s >'\
            .format(self.user_id, self.last_successful_challenge)

    def __str__(self):
        return self.__repr__().encode('ascii', 'ignore')