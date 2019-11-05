from ckan.lib.cli import CkanCommand

import sys


class Security(CkanCommand):
    '''Command for managing the security module
        Usage: paster --plugin=ckanext-security security <command> -c <path to config file>

            command:
            help  - prints this help
            migrate - create the database table to support time based one time (TOTP) login
        '''
    summary = __doc__.split('\n')[0]
    usage = __doc__

    def command(self):
        # load pylons config
        self._load_config()
        options = {
            'migrate': self.migrate,
            'help': self.help,
        }

        try:
            cmd = self.args[0]
            options[cmd](*self.args[1:])
        except KeyError:
            self.help()
            sys.exit(1)

    def help(self):
        print self.__doc__

    def migrate(self):
        print("Migrating database for security")
        from ckanext.security.model import db_setup
        db_setup()
        print("finished tables setup for security")
