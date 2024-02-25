from setuptools import setup, find_packages

version = '3.0.4'

setup(
    name='ckanext-security',
    version=version,
    description='Various security patches for CKAN',
    long_description='',
    # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[],
    keywords='',
    author='Data.govt.nz',
    author_email='info@data.govt.nz',
    url='https://www.data.govt.nz',
    license='',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    namespace_packages=['ckanext'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[],
    dependency_links=[],
    entry_points="""
    [ckan.plugins]
    security=ckanext.security.plugin:CkanSecurityPlugin
    """,
)
