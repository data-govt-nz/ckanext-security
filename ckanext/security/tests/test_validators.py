import ckan.model as model
import ckan.tests.factories as factories
import pytest
from ckan.lib.navl.dictization_functions import Invalid
from ckan.plugins import toolkit as tk
from passlib.handlers.pbkdf2 import pbkdf2_sha512

import ckanext.security.validators as validators
from ckanext.security.constants import PLUGIN_EXTRAS_BLACKLIST_KEY


class TestValidators(object):

    def test_password_length_default(self):
        """Check if the default password length is set to 10"""
        # WHEN
        actual = validators._min_password_length()
        # THEN
        assert actual == 10

    @pytest.mark.ckan_config(u'ckanext.security.min_password_length', u'12')
    def test_password_length_config(self):
        """Check if the password length is set to 12 when set via config"""
        # WHEN
        actual = validators._min_password_length()
        # THEN
        assert actual == 12

    @pytest.mark.ckan_config(u'ckanext.security.min_password_length', u'12')
    def test_valid_password_length_is_ok(self):
        """Check if the password length is validated correctly"""
        # WHEN + THEN
        validators.user_password_validator("pw", {"pw": "Aa_123456789"}, None, None)

    @pytest.mark.ckan_config(u'ckanext.security.min_password_length', u'12')
    def test_invalid_password_length_is_too_short(self):
        """Check if the password length is validated correctly"""
        # WHEN + THEN
        with pytest.raises(Invalid):
            validators.user_password_validator("pw", {"pw": "Aa_12345678"}, None, None)

    # Check if one missing character class still validates.
    def test_valid_no_uppercase_letters(self):
        # WHEN + THEN
        validators.user_password_validator("pw", {"pw": "aa_123456789"}, None, None)

    def test_valid_no_lowercase_letters(self):
        # WHEN + THEN
        validators.user_password_validator("pw", {"pw": "AA_123456789"}, None, None)

    def test_valid_no_special_chars(self):
        # WHEN + THEN
        validators.user_password_validator("pw", {"pw": "Aa0123456789"}, None, None)

    def test_valid_no_digits(self):
        # WHEN + THEN
        validators.user_password_validator("pw", {"pw": "Aa_abcdefghij"}, None, None)

    # Some checks to test character class validation.
    # We have to test in combinations, since one class missing is accepted and we want a fail.
    def test_invalid_no_uppercase_letters_and_no_lowercase_letters(self):
        # WHEN + THEN
        with pytest.raises(Invalid):
            validators.user_password_validator("pw", {"pw": "___123456789"}, None, None)

    def test_invalid_no_lowercase_letters_and_no_special_chars(self):
        # WHEN + THEN
        with pytest.raises(Invalid):
            validators.user_password_validator("pw", {"pw": "AAA123456789"}, None, None)

    def test_invalid_no_special_chars_and_no_digits(self):
        # WHEN + THEN
        with pytest.raises(Invalid):
            validators.user_password_validator("pw", {"pw": "Aaaaaaaaaaaaa"}, None, None)

    def test_invalid_no_digits_and_no_uppercase_letters(self):
        # WHEN + THEN
        with pytest.raises(Invalid):
            validators.user_password_validator("pw", {"pw": "aa_abcdefghij"}, None, None)

    @pytest.mark.usefixtures("with_plugins")
    @pytest.mark.ckan_config("ckan.plugins", "security")
    @pytest.mark.ckan_config(u'ckanext.security.blacklist_item_count', u'10')
    def test_password_on_blacklist_should_fail(self):
        """ If password is on blacklist, validator should throw an exception. """
        # GIVEN
        PASSWORD = "ckan4Password"
        user = factories.Sysadmin(password=PASSWORD)
        user_obj = model.User.get(user["name"])
        print(user)
        context = {"user": user["name"], 'model': model, 'user_obj': user_obj}

        # WHEN + THEN
        with pytest.raises(Invalid):
            validators.user_password_validator("pw", {"pw": PASSWORD}, None, context)

    def test_password_not_on_blacklist_should_succeed(self):
        """ If password is not on blacklist, validator should not throw an exception. """

        # GIVEN
        PASSWORD = "ckan4Password"
        hashed_password = str(pbkdf2_sha512.encrypt(PASSWORD))
        user = factories.User(password=PASSWORD,
                              plugin_extras={PLUGIN_EXTRAS_BLACKLIST_KEY: [hashed_password]})
        user_obj = model.User.get(user["name"])
        context = {"user": user["name"], 'model': model, 'user_obj': user_obj}

        # WHEN + THEN
        try:
            validators.user_password_validator("pw", {"pw": "ckan4Password2"}, None, context)
        except Invalid:
            pytest.fail("Validator threw an exception, but it should not have.")
