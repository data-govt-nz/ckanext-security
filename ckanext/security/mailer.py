# encoding: utf-8
import os
import codecs
import logging
import six

from ckan.common import config, is_flask_request
from ckan.lib.base import render_jinja2, render
from ckan.lib.mailer import get_reset_link_body, mail_user
import ckan.lib.mailer as mailer  # (canada fork only): GC Notify support
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


def _build_template(file_path, replacements={}):
    # (canada fork only): fixes app context
    # TODO: upstream contrib??
    template = ''
    with open(file_path, 'r') as f:
        template = f.read()
        for replacement, value in replacements.items():
            template = template.replace("{{ %s }}" % replacement, str(value))\
                .replace("{{%s}}" % replacement, str(value))
    return template


def _get_template(template_name):
    # (canada fork only): fixes app context
    # TODO: upstream contrib??
    # FIXME: this prevents users from being able to extend/override
    #        the email txt files in the templates directories.
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'templates/security/emails/%s' % template_name)


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
    # (canada fork only): fixes app context
    # TODO: upstream contrib??
    custom_path = config.get('ckanext.security.brute_force_footer_path')
    if (custom_path and os.path.exists(custom_path)):
        log.warning('Overriding brute force lockout email footer with %s',
                    custom_path)
        return '\n\n' + _build_template(custom_path, extra_vars)
    else:
        return '\n\n' + _build_template(_get_template('lockout_footer.txt'), extra_vars)


def notify_lockout(user, lockout_timeout):
    # (canada fork only): GC Notify support
    try:
        # see: ckanext.gcnotify.mailer.notify_lockout
        mailer.notify_lockout(user, lockout_timeout)
    except (mailer.MailerException, AttributeError, TypeError):
        extra_vars = {
            'site_title': config.get('ckan.site_title'),
            'site_url': config.get('ckan.site_url'),
            'user_name': user.name,
            'password_reset_url':
                config.get('ckan.site_url').rstrip('/') + '/user/login',
            'lockout_mins': int(lockout_timeout / 60),
        }

        # (canada fork only): fixes app context
        # TODO: upstream contrib??
        subject = _build_template(_get_template('lockout_subject.txt'), extra_vars)
        subject = subject.split('\n')[0]  # Make sure we only use the first line

        body = _build_template(_get_template('lockout_mail.txt'), extra_vars)\
            + _build_footer_content(extra_vars)

        mail_user(user, subject, body)
