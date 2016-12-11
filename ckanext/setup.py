from setuptools import setup, find_packages

version = '0.0.1'

setup(
    name='ckanext-dia',
    version=version,
    description='Various security patches for CKAN',
    long_description='',
    classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    keywords='',
    author='CKAN Team at Catalyst IT',
    author_email='ckan-dev@catalyst.net.nz',
    url='https://www.catalyst.net.nz',
    license='',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    namespace_packages=['ckanext', 'ckanext.dia'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        # -*- Extra requirements: -*-
    ],
    entry_points=\
    """
    [ckan.plugins]
    catsec=ckanext.security.plugin:SecurityPlugin
    """,
)
