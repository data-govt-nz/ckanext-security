# encoding: utf-8

from __future__ import print_function
import datetime
import logging
import pyotp

from ckan.model import DomainObject, User
from ckan.plugins import toolkit as tk
import sqlalchemy as sa

types = sa.types
Column = sa.Column

log = logging.getLogger(__name__)


class ReplayAttackException(Exception):
    """Thrown when we detect an attempted replay attack"""

    pass


class SecurityTOTP(DomainObject, tk.BaseModel):
    __tablename__ = "user_security_totp"
    id = Column(sa.Integer, primary_key=True, autoincrement=True)
    user_id = Column(sa.UnicodeText, default="")
    secret = Column(sa.UnicodeText, default="")
    last_successful_challenge = Column(sa.DateTime)

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
        """Finds a securityTOTP object using the user name
        :raises ValueError if the user_name is not provided
        """
        if user_name is None:
            raise ValueError("User name parameter must be supplied")

        challenger = (
            SecurityTOTP.Session.query(SecurityTOTP)
            .join(User, User.id == SecurityTOTP.user_id)
            .filter(User.name == user_name)
            .first()
        )
        return challenger

    def check_code(self, code, verify_only=False):
        """Checks that a one time password is correct against the model
        :raises ReplayAttackException if the code has already been used
         before, and is being used again
        :return boolean true if the code is valid
        """
        totp = pyotp.TOTP(self.secret)
        # valid_window means that the code will verify in the next 30s
        # window as well
        result = totp.verify(code, valid_window=1)
        if result and not verify_only:
            # check for replay attack...
            if (
                self.last_successful_challenge
                and totp.at(self.last_successful_challenge) == code
            ):
                raise ReplayAttackException("the replay code has already been used")

            self.last_successful_challenge = datetime.datetime.utcnow()
            self.save()
        else:
            log.debug("Failed to verify the totp code")
        return result

    @property
    def provisioning_uri(self):
        """Returns the uri for setting up a QR code"""
        user = self.Session.query(User).filter(User.id == self.user_id).first()
        if user is None:
            raise ValueError(
                "No user found for SecurityTOTP instance with user_id {}".format(
                    self.user_id
                )
            )

        issuer = tk.config["ckan.site_url"]
        return pyotp.TOTP(self.secret).provisioning_uri(user.name, issuer_name=issuer)

    def __repr__(self):
        return "<SecurityTOTP user_id={} last_successful_challenge={} >".format(
            self.user_id, self.last_successful_challenge
        )

    def __str__(self):
        return self.__repr__().encode("ascii", "ignore")
