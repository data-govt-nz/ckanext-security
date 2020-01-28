import datetime

from ckan import model
from ckan.model import DomainObject, User
from ckan.model.meta import metadata,  mapper, Session
import ckan.plugins.toolkit as toolkit
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
                               Column('last_successful_challenge', types.DateTime))

    mapper(
        SecurityTOTP,
        user_security_totp
    )


class ReplayAttackException(Exception):
    """Thrown when we detect an attempted replay attack"""
    pass


class SecurityTOTP(DomainObject):
    @classmethod
    def create_for_user(cls, user_name):
        """
        Set up the
        :param user_name:
        :return:  SecurityTOTP model -- saved
        """
        if user_name is None:
            raise ValueError("User name parameter must be supplied")
        new_secret = pyotp.random_base32()
        security_challenge = cls.get_for_user(user_name)
        user = SecurityTOTP.Session.query(User).filter(User.name == user_name).first()

        if security_challenge is None:
            security_challenge = SecurityTOTP(user_id=user.id, secret=new_secret)
        else:
            security_challenge.secret = new_secret

        security_challenge.last_successful_challenge = None
        security_challenge.save()
        return security_challenge

    @classmethod
    def get_for_user(cls, user_name):
        '''Finds a securityTOTP object using the user name
        :raises ValueError if the user_name is not provided
        '''
        if user_name is None:
            raise ValueError("User name parameter must be supplied")

        challenger = SecurityTOTP.Session.query(SecurityTOTP)\
            .join(User, User.id == SecurityTOTP.user_id) \
            .filter(User.name == user_name).first()
        return challenger


    def check_code(self, code, verify_only=False):
        """ Checks that a one time password is correct against the model
        :raises ReplayAttackException if the code has already been used before, and it is attempted to be used again
        :return boolean true if the code is valid
        """
        totp = pyotp.TOTP(self.secret)
        result = totp.verify(code)
        if result and not verify_only:
            # check for replay attack...
            if self.last_successful_challenge and totp.at(self.last_successful_challenge) == code:
                raise ReplayAttackException("the replay code has already been used")

            self.last_successful_challenge = datetime.datetime.utcnow()
            self.save()
        else:
            log.debug("Failed to verify the totp code")
        return result

    @property
    def provisioning_uri(self):
        """Returns the uri for setting up a QR code
        """
        user = self.Session.query(User)\
            .filter(User.id == self.user_id).first()
        if user is None:
            raise ValueError('No user found for SecurityTOTP instance with user_id {}'.format(self.user_id))

        issuer = toolkit.config['ckan.site_url']
        return pyotp.TOTP(self.secret)\
            .provisioning_uri(user.name, issuer_name=issuer)

    def __repr__(self):
        return '<SecurityTOTP user_id={} last_successful_challenge={} >'\
            .format(self.user_id, self.last_successful_challenge)

    def __str__(self):
        return self.__repr__().encode('ascii', 'ignore')
