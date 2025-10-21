"""
Tests for index operations
"""

import pytest
from infino_sdk.lib import InfinoSDK, InfinoError


@pytest.mark.unit
def test_create_index(sdk_with_mock_session, mock_response):
    """Test index creation"""
    sdk = sdk_with_mock_session
    
    create_response = {"acknowledged": True, "shards_acknowledged": True, "index": "test_index"}
    response = mock_response(200, create_response)
    sdk.session.request.return_value = response
    
    result = sdk.create_index("test_index")
    
    assert result["acknowledged"] is True
    assert result["index"] == "test_index"


@pytest.mark.unit
def test_create_index_already_exists(sdk_with_mock_session, mock_response):
    """Test creating index that already exists"""
    sdk = sdk_with_mock_session
    
    response = mock_response(409, text="resource_already_exists_exception")
    sdk.session.request.return_value = response
    
    # SDK should handle 409 gracefully
    result = sdk.create_index("existing_index")
    
    assert result["acknowledged"] is True


@pytest.mark.unit
def test_create_index_with_mapping(sdk_with_mock_session, mock_response):
    """Test index creation with custom mapping"""
    sdk = sdk_with_mock_session
    
    create_response = {"acknowledged": True, "shards_acknowledged": True, "index": "test_index"}
    response = mock_response(200, create_response)
    sdk.session.request.return_value = response
    
    mapping = {
        "mappings": {
            "properties": {
                "title": {"type": "text"},
                "price": {"type": "float"}
            }
        }
    }
    
    result = sdk.create_index_with_mapping("test_index", mapping)
    
    assert result["acknowledged"] is True


@pytest.mark.unit
def test_delete_index(sdk_with_mock_session, mock_response):
    """Test index deletion"""
    sdk = sdk_with_mock_session
    
    delete_response = {"acknowledged": True}
    response = mock_response(200, delete_response)
    sdk.session.request.return_value = response
    
    result = sdk.delete_index("test_index")
    
    assert result["acknowledged"] is True


@pytest.mark.unit
def test_get_index(sdk_with_mock_session, mock_response, sample_index_response):
    """Test getting index information"""
    sdk = sdk_with_mock_session
    
    response = mock_response(200, sample_index_response)
    sdk.session.request.return_value = response
    
    result = sdk.get_index("test_index")
    
    assert "test_index" in result
    assert "mappings" in result["test_index"]
    assert "settings" in result["test_index"]


@pytest.mark.unit
def test_get_cat_indices(sdk_with_mock_session, mock_response):
    """Test listing indices"""
    sdk = sdk_with_mock_session
    
    indices_response = [
        {"health": "green", "status": "open", "index": "index1", "docs.count": "100"},
        {"health": "yellow", "status": "open", "index": "index2", "docs.count": "50"}
    ]
    response = mock_response(200, indices_response)
    sdk.session.request.return_value = response
    
    result = sdk.cat_indices()
    
    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["index"] == "index1"


@pytest.mark.unit
def test_get_schema(sdk_with_mock_session, mock_response):
    """Test getting index schema"""
    sdk = sdk_with_mock_session
    
    schema_response = {
        "fields": [
            {"name": "title", "type": "text"},
            {"name": "price", "type": "float"}
        ]
    }
    response = mock_response(200, schema_response)
    sdk.session.request.return_value = response
    
    result = sdk.get_schema("test_index")
    
    assert "fields" in result
    assert len(result["fields"]) == 2


@pytest.mark.unit
def test_get_mappings(sdk_with_mock_session, mock_response):
    """Test getting index mappings"""
    sdk = sdk_with_mock_session
    
    mappings_response = {
        "test_index": {
            "mappings": {
                "properties": {
                    "title": {"type": "text"}
                }
            }
        }
    }
    response = mock_response(200, mappings_response)
    sdk.session.request.return_value = response
    
    result = sdk.get_mappings("test_index")
    
    assert "test_index" in result
    assert "mappings" in result["test_index"]
