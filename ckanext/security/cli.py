# -*- coding: utf-8 -*-

import click

from ckanext.security.model import db_setup, SecurityTOTP


def get_commands():
    return [security]


@click.group(short_help="Command for managing the security module.")
def security():
    pass


@security.command()
def migrate():
    db_setup()


@security.command()
@click.argument('username')
def reset_totp(username):
     SecurityTOTP.create_for_user(username)