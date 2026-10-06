"""Regression tests for profile images in the user schemas."""

import pytest

from ckan.lib.navl.dictization_functions import validate
from ckanext.security import schema


@pytest.mark.parametrize('schema_factory', [
    schema.default_user_schema,
    schema.default_update_user_schema,
    schema.user_new_form_schema,
    schema.user_edit_form_schema,
])
@pytest.mark.parametrize('image_fields', [
    {},
    {'image_url': 'https://example.org/profile.png'},
    {'image_url': '', 'image_display_url': ''},
    {
        'image_url': 'profile.png',
        'image_display_url': 'https://example.org/whakaahua.png',
    },
])
def test_profile_image_fields_survive_validation(schema_factory, image_fields):
    """Missing, linked, uploaded and cleared images retain core behaviour."""
    user_schema = schema_factory()
    # Validate the image fields through NAVL without unrelated account fields.
    image_schema = {
        key: user_schema[key]
        for key in ('image_url', 'image_display_url')
        if key in user_schema
    }
    data, errors = validate(image_fields, image_schema, {})

    assert errors == {}
    for key, value in image_fields.items():
        assert data[key] == value
    assert not data.get('__extras')
