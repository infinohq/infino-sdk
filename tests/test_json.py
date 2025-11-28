"""
Tests for bulk upload operations
"""

import pytest

from infino_sdk.lib import InfinoError, InfinoSDK


@pytest.mark.unit
def test_upload_json_to_dataset_success(
    sdk_with_mock_session, mock_response, sample_bulk_response
):
    """Test successful record upload"""
    sdk = sdk_with_mock_session

    response = mock_response(200, sample_bulk_response)
    sdk.session.request.return_value = response

    bulk_data = """
{"index": {"_id": "1"}}
{"name": "Product 1", "price": 29.99}
{"index": {"_id": "2"}}
{"name": "Product 2", "price": 49.99}
"""

    result = sdk.upload_json_to_dataset("test_dataset", bulk_data)

    assert result["errors"] is False
    assert len(result["items"]) == 2


@pytest.mark.unit
def test_upload_json_to_dataset_with_errors(sdk_with_mock_session, mock_response):
    """Test record upload with some failures"""
    sdk = sdk_with_mock_session

    bulk_response = {
        "took": 30,
        "errors": True,
        "items": [
            {
                "index": {
                    "_index": "test_index",
                    "_id": "1",
                    "_version": 1,
                    "result": "created",
                    "status": 201,
                }
            },
            {
                "index": {
                    "_index": "test_index",
                    "_id": "2",
                    "status": 400,
                    "error": {
                        "type": "mapper_parsing_exception",
                        "reason": "failed to parse field",
                    },
                }
            },
        ],
    }

    response = mock_response(200, bulk_response)
    sdk.session.request.return_value = response

    bulk_data = """
{"index": {"_id": "1"}}
{"name": "Product 1"}
{"index": {"_id": "2"}}
{"invalid": "data"}
"""

    result = sdk.upload_json_to_dataset("test_dataset", bulk_data)

    assert result["errors"] is True
    assert len(result["items"]) == 2


@pytest.mark.unit
def test_upload_json_to_dataset_auto_add_newline(
    sdk_with_mock_session, mock_response, sample_bulk_response
):
    """Test that upload_json_to_dataset adds newline if missing"""
    sdk = sdk_with_mock_session

    response = mock_response(200, sample_bulk_response)
    sdk.session.request.return_value = response

    # Data without trailing newline
    bulk_data = '{"index": {"_id": "1"}}\n{"name": "Product 1"}'

    result = sdk.upload_json_to_dataset("test_dataset", bulk_data)

    assert result["errors"] is False


@pytest.mark.unit
def test_bulk_update(sdk_with_mock_session, mock_response):
    """Test bulk update operations"""
    sdk = sdk_with_mock_session

    bulk_response = {
        "took": 30,
        "errors": False,
        "items": [
            {
                "update": {
                    "_index": "test_index",
                    "_id": "1",
                    "_version": 2,
                    "result": "updated",
                    "status": 200,
                }
            }
        ],
    }

    response = mock_response(200, bulk_response)
    sdk.session.request.return_value = response

    bulk_data = """
{"update": {"_id": "1"}}
{"doc": {"price": 39.99}}
"""

    result = sdk.upload_json_to_dataset("test_dataset", bulk_data)

    assert result["errors"] is False
    assert result["items"][0]["update"]["result"] == "updated"


@pytest.mark.unit
def test_bulk_delete(sdk_with_mock_session, mock_response):
    """Test bulk delete operations"""
    sdk = sdk_with_mock_session

    bulk_response = {
        "took": 30,
        "errors": False,
        "items": [
            {
                "delete": {
                    "_index": "test_index",
                    "_id": "1",
                    "_version": 3,
                    "result": "deleted",
                    "status": 200,
                }
            }
        ],
    }

    response = mock_response(200, bulk_response)
    sdk.session.request.return_value = response

    bulk_data = '{"delete": {"_id": "1"}}\n'

    result = sdk.upload_json_to_dataset("test_dataset", bulk_data)

    assert result["errors"] is False
    assert result["items"][0]["delete"]["result"] == "deleted"
