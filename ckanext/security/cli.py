# -*- coding: utf-8 -*-

from __future__ import print_function
import click

from ckanext.security.model import db_setup, SecurityTOTP


def get_commands():
    return [security]


@click.group(short_help="Commands for managing the security module.")
def security():
    pass


@security.command()
def migrate():
    """
    Create the database table to support Time-based One Time Password login
    """
    print("Migrating database for security")
    db_setup()
    print("finished tables setup for security")


@security.command()
@click.argument('username')
def reset_totp(username):
    """
    Generate a new totp secret for a given user
    """
    print('Resetting totp secret for user {}'.format(username))
    SecurityTOTP.create_for_user(username)
    print('Success!')
