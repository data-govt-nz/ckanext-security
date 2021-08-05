from __future__ import print_function

import sys
from ckan.lib.cli import CkanCommand

from ckanext.security.model import db_setup, SecurityTOTP


class Security(CkanCommand):
    '''Command for managing the security module.

    Usage:

        security help
            - prints this help

        security migrate
            - create the database table to support Time-based One Time
              Password login

        security reset_totp <username>
            - generate a new totp secret for a given user
    '''
    summary = __doc__.split('\n')[0]
    usage = __doc__

    def command(self):
        # load pylons config
        self._load_config()
        options = {
            'migrate': self.migrate,
            'help': self.help,
            'reset_totp': self.reset_totp,
        }

        try:
            cmd = self.args[0]
            options[cmd](*self.args[1:])
        except (KeyError, IndexError):
            self.help()
            sys.exit(1)

    def help(self):
        print(self.__doc__)

    def migrate(self):
        print("Migrating database for security")
        db_setup()
        print("finished tables setup for security")

    def reset_totp(self, username):
        print('Resetting totp secret for user', username)
        SecurityTOTP.create_for_user(username)
        print('Success!')
