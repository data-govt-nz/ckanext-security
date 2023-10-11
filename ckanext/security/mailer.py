# encoding: utf-8
import os
import codecs
import logging
import six
import flask

from ckan.common import config
from ckan.lib.base import render
from ckan.lib.mailer import get_reset_link_body, mail_user
from ckan import model


log = logging.getLogger(__name__)


def make_key():
    return codecs.encode(os.urandom(16), 'hex')


def create_reset_key(user):
    user.reset_key = six.ensure_text(make_key())
    model.repo.commit_and_remove()


def send_reset_link(user):
    create_reset_key(user)
    body = get_reset_link_body(user)
    extra_vars = {
        'site_title': config.get('ckan.site_title')
    }
    subject = render(
        'emails/reset_password_subject.txt', extra_vars)

    # Make sure we only use the first line
    subject = subject.split('\n')[0]

    mail_user(user, subject, body)


def _build_footer_content(extra_vars):
    custom_path = config.get('ckanext.security.brute_force_footer_path')
    if (custom_path and os.path.exists(custom_path)):
        log.warning('Overriding brute force lockout email footer with %s',
                    custom_path)
        with open(custom_path, 'r') as footer_file:
            footer_content = footer_file.read()
        env = flask.current_app.jinja_env
        template = env.from_string(footer_content)
        return '\n\n' + template.render(**extra_vars)
    else:
        footer_path = 'security/emails/lockout_footer.txt'
        return '\n\n' + render(footer_path, extra_vars)


def notify_lockout(user, lockout_timeout):
    extra_vars = {
        'site_title': config.get('ckan.site_title'),
        'site_url': config.get('ckan.site_url'),
        'user_name': user.name,
        'password_reset_url':
            config.get('ckan.site_url').rstrip('/') + '/user/login',
        'lockout_mins': lockout_timeout // 60,
    }

    subject = render(
        'security/emails/lockout_subject.txt', extra_vars)

    subject = subject.split('\n')[0]  # Make sure we only use the first line

    body = render('security/emails/lockout_mail.txt', extra_vars)\
        + _build_footer_content(extra_vars)

    mail_user(user, subject, body)
