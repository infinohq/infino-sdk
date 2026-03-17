"""
Tests for new dataset operations: get_dataset, create_dataset_with_mapping, count, flush
"""

import json
from unittest.mock import Mock

import pytest

from infino_sdk.lib import InfinoError, InfinoSDK


@pytest.mark.unit
def test_get_dataset(sdk_with_mock_session, mock_response):
    """Test get_dataset returns index info"""
    sdk = sdk_with_mock_session

    dataset_info = {
        "test_dataset": {
            "aliases": {},
            "mappings": {"properties": {"name": {"type": "text"}}},
        }
    }
    response = mock_response(200, dataset_info)
    sdk.session.request.return_value = response

    result = sdk.get_dataset("test_dataset")

    assert "test_dataset" in result
    sdk.session.request.assert_called_once()
    call_args = sdk.session.request.call_args
    assert call_args.kwargs["method"] == "GET"
    assert call_args.kwargs["url"].endswith("/test_dataset")


@pytest.mark.unit
def test_create_dataset_with_mapping(sdk_with_mock_session, mock_response):
    """Test creating a dataset with explicit mappings"""
    sdk = sdk_with_mock_session

    create_response = {
        "acknowledged": True,
        "shards_acknowledged": True,
        "index": "my-dataset.sem",
    }
    response = mock_response(200, create_response)
    sdk.session.request.return_value = response

    mapping = {
        "mappings": {
            "properties": {
                "title": {"type": "text"},
                "embedding": {"type": "knn_vector", "dimension": 384},
            }
        }
    }
    result = sdk.create_dataset_with_mapping("my-dataset.sem", mapping)

    assert result["acknowledged"] is True
    assert result["index"] == "my-dataset.sem"
    call_args = sdk.session.request.call_args
    assert call_args.kwargs["method"] == "PUT"
    body = json.loads(call_args.kwargs["data"])
    assert "mappings" in body


@pytest.mark.unit
def test_count(sdk_with_mock_session, mock_response):
    """Test count returns document count"""
    sdk = sdk_with_mock_session

    count_response = {"count": 1500}
    response = mock_response(200, count_response)
    sdk.session.request.return_value = response

    result = sdk.count("test_dataset")

    assert result["count"] == 1500
    call_args = sdk.session.request.call_args
    assert call_args.kwargs["url"].endswith("/test_dataset/_count")


@pytest.mark.unit
def test_flush(sdk_with_mock_session, mock_response):
    """Test flush commits uncommitted segments"""
    sdk = sdk_with_mock_session

    flush_response = {"_shards": {"total": 2, "successful": 2, "failed": 0}}
    response = mock_response(200, flush_response)
    sdk.session.request.return_value = response

    result = sdk.flush()

    assert result["_shards"]["failed"] == 0
    call_args = sdk.session.request.call_args
    assert call_args.kwargs["method"] == "POST"
    assert call_args.kwargs["url"].endswith("/_flush")
