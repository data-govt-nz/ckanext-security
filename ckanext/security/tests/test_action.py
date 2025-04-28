import ckan.model as model
import ckan.tests.factories as factories
import ckanext.security.logic.action as action
import pytest
from ckan.plugins import toolkit as tk
from ckanext.security.constants import PLUGIN_EXTRAS_TABULIST_KEY
from passlib.hash import pbkdf2_sha512


class TestAction(object):

    @pytest.mark.ckan_config(u'ckanext.security.tabulist_item_count', u'2')
    def test_append_password(self):
        """
        Check if the password is appended to the list of forbidden passwords
        AND the list is limited to 2 entries.
        """

        # GIVEN
        user = factories.Sysadmin()
        user_obj = model.User.get(user["name"])
        context = {"user": user["name"], "ignore_auth": True}

        # WHEN
        user_obj.password = "new_password1"
        action._append_password(context, user_obj) # 1st entry in tabu list

        user_obj.password = "new_password2"
        action._append_password(context, user_obj) # 2nd entry in tabu list

        user_obj.password = "new_password3"
        action._append_password(context, user_obj) # will replace the last entry in tabu list

        # THEN
        actual_user = tk.get_action('user_show')(context, {'id': user['name'], 'include_plugin_extras': True})
        assert 'plugin_extras' in actual_user
        assert PLUGIN_EXTRAS_TABULIST_KEY in actual_user['plugin_extras']
        assert len(actual_user['plugin_extras'][PLUGIN_EXTRAS_TABULIST_KEY]) == 2
        assert pbkdf2_sha512.verify("new_password3", actual_user['plugin_extras'][PLUGIN_EXTRAS_TABULIST_KEY][0])
        assert pbkdf2_sha512.verify("new_password2", actual_user['plugin_extras'][PLUGIN_EXTRAS_TABULIST_KEY][1])

    @pytest.mark.usefixtures("with_plugins")
    @pytest.mark.ckan_config("ckan.plugins", "security")
    @pytest.mark.ckan_config(u'ckanext.security.tabulist_item_count', u'10')
    def test_user_update_password_append_is_called(self):
        """Check if when updating the password, the append function is called."""

        # GIVEN
        user = factories.Sysadmin(password="ckan4Password")
        context = {"user": user["name"]}

        # WHEN
        tk.get_action('user_patch')(context, {'id': user['name'], 'password': 'ckan4Password2'})

        # THEN
        actual_user = tk.get_action('user_show')(context, {'id': user['name'], 'include_plugin_extras': True})

        assert 'plugin_extras' in actual_user
        assert actual_user['plugin_extras'] is not None
        assert PLUGIN_EXTRAS_TABULIST_KEY in actual_user['plugin_extras']
        # make sure there are 2 entries: 1st: user_create, 2nd: user_update
        assert len(actual_user['plugin_extras'][PLUGIN_EXTRAS_TABULIST_KEY]) == 2