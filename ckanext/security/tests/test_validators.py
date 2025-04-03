import pytest
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

