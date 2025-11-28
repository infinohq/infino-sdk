"""
Tests for dataset operations
"""

import pytest

from infino_sdk.lib import InfinoError, InfinoSDK


@pytest.mark.unit
def test_create_dataset(sdk_with_mock_session, mock_response):
    """Test dataset creation"""
    sdk = sdk_with_mock_session

    create_response = {
        "acknowledged": True,
        "shards_acknowledged": True,
        "index": "test_dataset",
    }
    response = mock_response(200, create_response)
    sdk.session.request.return_value = response

    result = sdk.create_dataset("test_dataset")

    assert result["acknowledged"] is True
    assert result["index"] == "test_dataset"


@pytest.mark.unit
def test_create_dataset_already_exists(sdk_with_mock_session, mock_response):
    """Test creating dataset that already exists"""
    sdk = sdk_with_mock_session

    response = mock_response(409, text="resource_already_exists_exception")
    sdk.session.request.return_value = response

    # SDK should handle 409 gracefully
    result = sdk.create_dataset("existing_dataset")

    assert result["acknowledged"] is True


# Test removed - create_dataset_with_mapping not in public SDK


@pytest.mark.unit
def test_delete_dataset(sdk_with_mock_session, mock_response):
    """Test dataset deletion"""
    sdk = sdk_with_mock_session

    delete_response = {"acknowledged": True}
    response = mock_response(200, delete_response)
    sdk.session.request.return_value = response

    result = sdk.delete_dataset("test_dataset")

    assert result["acknowledged"] is True


@pytest.mark.unit
def test_get_dataset_metadata(sdk_with_mock_session, mock_response):
    """Test getting dataset metadata"""
    sdk = sdk_with_mock_session

    metadata_response = {"status": "open", "health": "green"}
    response = mock_response(200, metadata_response)
    sdk.session.request.return_value = response

    result = sdk.get_dataset_metadata("test_dataset")

    assert result["status"] == "open"
    assert result["health"] == "green"


@pytest.mark.unit
def test_get_datasets(sdk_with_mock_session, mock_response):
    """Test listing all datasets"""
    sdk = sdk_with_mock_session

    datasets_response = [
        {"health": "green", "status": "open", "index": "dataset1", "docs.count": "100"},
        {"health": "yellow", "status": "open", "index": "dataset2", "docs.count": "50"},
    ]
    response = mock_response(200, datasets_response)
    sdk.session.request.return_value = response

    result = sdk.get_datasets()

    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["index"] == "dataset1"


@pytest.mark.unit
def test_get_dataset_schema(sdk_with_mock_session, mock_response):
    """Test getting dataset schema"""
    sdk = sdk_with_mock_session

    schema_response = {
        "fields": [
            {"name": "title", "type": "text"},
            {"name": "price", "type": "float"},
        ]
    }
    response = mock_response(200, schema_response)
    sdk.session.request.return_value = response

    result = sdk.get_dataset_schema("test_dataset")

    assert "fields" in result
    assert len(result["fields"]) == 2


# Test removed - get_mappings/get_field_mappings not in simplified public API
