# encoding: utf-8
import os
import codecs
import logging
import six
import flask

from ckan.plugins.toolkit import config, render, check_ckan_version
from ckan.lib.mailer import get_reset_link_body, mail_user
from ckan import model


log = logging.getLogger(__name__)


def make_key():
    return codecs.encode(os.urandom(16), 'hex')


def create_reset_key(user):
    user.reset_key = six.ensure_text(make_key())
    model.repo.commit_and_remove()


def _build_template(file_path, replacements={}):
    template = ''
    with open(file_path, 'r') as f:
        template = f.read()
        for replacement, value in replacements.items():
            template = template.replace("{{ %s }}" % replacement, str(value))\
                .replace("{{%s}}" % replacement, str(value))
    return template


def _get_template(template_name):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'templates/security/emails/%s' % template_name)


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
        if check_ckan_version(min_version='2.10'):
            with open(custom_path, 'r') as footer_file:
                footer_content = footer_file.read()
            env = flask.current_app.jinja_env
            template = env.from_string(footer_content)
            return '\n\n' + template.render(**extra_vars)
        else:
            return '\n\n' + _build_template(custom_path, extra_vars)
    else:
        if check_ckan_version(min_version='2.10'):
            footer_path = 'security/emails/lockout_footer.txt'
            return '\n\n' + render(footer_path, extra_vars)
        else:
            return '\n\n' + _build_template(_get_template('lockout_footer.txt'), extra_vars)


def notify_lockout(user, lockout_timeout):
    extra_vars = {
        'site_title': config.get('ckan.site_title'),
        'site_url': config.get('ckan.site_url'),
        'user_name': user.name,
        'password_reset_url':
            config.get('ckan.site_url').rstrip('/') + '/user/login',
        'lockout_mins': lockout_timeout / 60,  # lockout is defined in seconds
    }

    if check_ckan_version(min_version='2.10'):
        subject = render('security/emails/lockout_subject.txt', extra_vars)
        body = render('security/emails/lockout_mail.txt', extra_vars)
    else:
        # FIXME: CKAN<=2.9 uses the repoze lib for the authentication stack.
        #        With this, at this point, there is no request or app context.
        #        So for CKAN<=2.9, we cannot support the Jinja2 app context.
        subject = _build_template(_get_template('lockout_subject.txt'), extra_vars)
        body = _build_template(_get_template('lockout_mail.txt'), extra_vars)

    subject = subject.split('\n')[0]  # Make sure we only use the first line
    body += _build_footer_content(extra_vars)

    mail_user(user, subject, body)
