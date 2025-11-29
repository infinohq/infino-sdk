"""
Tests for query operations
"""

import pytest

from infino_sdk.lib import InfinoError, InfinoSDK


@pytest.mark.unit
def test_query_querydsl_success(
    sdk_with_mock_session, mock_response, sample_search_response
):
    """Test successful QueryDSL query"""
    sdk = sdk_with_mock_session

    # Mock the response
    response = mock_response(200, sample_search_response)
    sdk.session.request.return_value = response

    result = sdk.query_dataset_in_querydsl(
        "test_dataset", '{"query": {"match_all": {}}}'
    )

    assert "hits" in result
    assert result["hits"]["total"]["value"] == 100
    assert len(result["hits"]["hits"]) == 2


@pytest.mark.unit
def test_query_querydsl_not_found(sdk_with_mock_session, mock_response):
    """Test query with non-existent dataset"""
    sdk = sdk_with_mock_session

    response = mock_response(404, text="index_not_found_exception")
    sdk.session.request.return_value = response

    with pytest.raises(InfinoError) as exc_info:
        sdk.search("nonexistent", '{"query": {"match_all": {}}}')

    assert exc_info.value.status_code() == 404


# Test removed - search_ai not in public SDK


@pytest.mark.unit
def test_count_records(sdk_with_mock_session, mock_response):
    """Test record count"""
    sdk = sdk_with_mock_session

    count_response = {"count": 42}
    response = mock_response(200, count_response)
    sdk.session.request.return_value = response

    result = sdk.count("test_dataset")

    assert result["count"] == 42


# Test removed - msearch not in public SDK
