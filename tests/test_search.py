"""
Tests for search operations
"""

import pytest
from infino_sdk.lib import InfinoSDK, InfinoError


@pytest.mark.unit
def test_search_success(sdk_with_mock_session, mock_response, sample_search_response):
    """Test successful search"""
    sdk = sdk_with_mock_session
    
    # Mock the response
    response = mock_response(200, sample_search_response)
    sdk.session.request.return_value = response
    
    result = sdk.search("test_index", '{"query": {"match_all": {}}}')
    
    assert "hits" in result
    assert result["hits"]["total"]["value"] == 100
    assert len(result["hits"]["hits"]) == 2


@pytest.mark.unit
def test_search_not_found(sdk_with_mock_session, mock_response):
    """Test search with non-existent index"""
    sdk = sdk_with_mock_session
    
    response = mock_response(404, text="index_not_found_exception")
    sdk.session.request.return_value = response
    
    with pytest.raises(InfinoError) as exc_info:
        sdk.search("nonexistent", '{"query": {"match_all": {}}}')
    
    assert exc_info.value.status_code() == 404


@pytest.mark.unit
def test_search_ai(sdk_with_mock_session, mock_response, sample_search_response):
    """Test AI-powered search"""
    sdk = sdk_with_mock_session
    
    response = mock_response(200, sample_search_response)
    sdk.session.request.return_value = response
    
    result = sdk.search_ai("test_index", "find me documents about testing")
    
    assert "hits" in result
    assert isinstance(result["hits"], dict)


@pytest.mark.unit
def test_count(sdk_with_mock_session, mock_response):
    """Test document count"""
    sdk = sdk_with_mock_session
    
    count_response = {"count": 42}
    response = mock_response(200, count_response)
    sdk.session.request.return_value = response
    
    result = sdk.count("test_index")
    
    assert result["count"] == 42


@pytest.mark.unit
def test_msearch(sdk_with_mock_session, mock_response):
    """Test multi-search"""
    sdk = sdk_with_mock_session
    
    msearch_response = {
        "responses": [
            {"hits": {"total": {"value": 10}}},
            {"hits": {"total": {"value": 20}}}
        ]
    }
    response = mock_response(200, msearch_response)
    sdk.session.request.return_value = response
    
    queries = '''
    {"index": "index1"}
    {"query": {"match_all": {}}}
    {"index": "index2"}
    {"query": {"match_all": {}}}
    '''
    
    result = sdk.msearch(queries)
    
    assert "responses" in result
    assert len(result["responses"]) == 2
