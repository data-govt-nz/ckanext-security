# encoding: utf-8
import os
import codecs
import logging
import six

from ckan.common import config, is_flask_request
from ckan.lib.base import render_jinja2, render
from ckan.lib.mailer import get_reset_link_body, mail_user
from ckan.plugins import toolkit as tk
from ckan import model

if tk.check_ckan_version('2.8'):
    import flask

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
    if is_flask_request():
        subject = render(
            'emails/reset_password_subject.txt', extra_vars)
    else:
        subject = render_jinja2(
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
        if is_flask_request():
            env = flask.current_app.jinja_env
        else:
            env = config['pylons.app_globals'].jinja_env
        template = env.from_string(footer_content)
        return '\n\n' + template.render(**extra_vars)
    else:
        footer_path = 'security/emails/lockout_footer.txt'
        if is_flask_request():
            return '\n\n' + render(footer_path, extra_vars)
        else:
            return '\n\n' + render_jinja2(footer_path, extra_vars)


def notify_lockout(user, lockout_timeout):
    extra_vars = {
        'site_title': config.get('ckan.site_title'),
        'site_url': config.get('ckan.site_url'),
        'user_name': user.name,
        'password_reset_url':
            config.get('ckan.site_url').rstrip('/') + '/user/login',
        'lockout_mins': lockout_timeout // 60,
    }

    if is_flask_request():
        subject = render(
            'security/emails/lockout_subject.txt', extra_vars)
    else:
        subject = render_jinja2(
            'security/emails/lockout_subject.txt', extra_vars)

    subject = subject.split('\n')[0]  # Make sure we only use the first line

    if is_flask_request():
        body = render('security/emails/lockout_mail.txt', extra_vars)\
            + _build_footer_content(extra_vars)
    else:
        body = render_jinja2('security/emails/lockout_mail.txt', extra_vars)\
            + _build_footer_content(extra_vars)

    mail_user(user, subject, body)
