import pytest
from ckan.lib.navl.dictization_functions import Invalid

import ckanext.security.validators as validators


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
