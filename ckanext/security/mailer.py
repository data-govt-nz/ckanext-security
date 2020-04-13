import os
import codecs

from ckan.common import config
from ckan.lib.base import render_jinja2
from ckan.lib.mailer import *
from ckan import model


def make_key():
    return codecs.encode(os.urandom(16), 'hex')


def create_reset_key(user):
    user.reset_key = unicode(make_key())
    model.repo.commit_and_remove()


def send_reset_link(user):
    create_reset_key(user)
    body = get_reset_link_body(user)
    extra_vars = {
        'site_title': config.get('ckan.site_title')
    }
    subject = render_jinja2('emails/reset_password_subject.txt', extra_vars)

    # Make sure we only use the first line
    subject = subject.split('\n')[0]

    mail_user(user, subject, body)


def notify_lockout(user):
    extra_vars = {
        'site_title': config.get('ckan.site_title'),
        'site_url': config.get('ckan.site_url'),
        'user_name': user.name,
    }

    subject = render_jinja2('security/emails/lockout_subject.txt', extra_vars)
    subject = subject.split('\n')[0]  # Make sure we only use the first line

    body = render_jinja2('security/emails/lockout_mail.txt', extra_vars)

    mail_user(user, subject, body)
