import pytest

class TestUtils(object):

    @pytest.mark.ckan_config(u'ckanext.security.min_password_length', u'12')
    def test_dummy(self):
        """ Basically a dummy test to check if the logger is initialized"""
        # WHEN
        # TODO dummy
        # THEN
        assert True
