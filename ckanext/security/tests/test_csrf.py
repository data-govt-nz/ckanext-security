"""
Test that tokens are applied to some valid HTML datasets
"""
import ckanext.security.anti_csrf as af


with open('./dataset.html') as f:
    test_case = f.read()
    result = af.apply_token(test_case, 'DEADBEEFEEDEADBEEF')
    assert 'DEADBEEFEEDEADBEEF' in result
    print("PASSED: a token is inserted into the dataset manage view")


with open('./harvest-admin-page.html') as f:
    test_case = f.read()
    result = af.apply_token(test_case, 'DEADBEEFEEDEADBEEF')
    assert 'DEADBEEFEEDEADBEEF' in result
    print("PASSED: a token is inserted into the harvest admin view")