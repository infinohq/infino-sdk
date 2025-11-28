"""
Pytest configuration and shared fixtures

Based on patterns from infino/tests/api/python/src/utils
"""

from typing import Any, Dict
from unittest.mock import MagicMock, Mock, patch

import pytest

from infino_sdk.lib import InfinoSDK, RetryConfig


def _attach_sdk_helpers(sdk: InfinoSDK) -> InfinoSDK:
    """Attaches helper methods and aliases expected by tests."""
    sdk.prom_ql_query = sdk.query_dataset_in_promql  # type: ignore[attr-defined]
    sdk.prom_ql_query_range = sdk.query_dataset_in_promql_range  # type: ignore[attr-defined]
    sdk.sql = sdk.query_dataset_in_sql  # type: ignore[attr-defined]
    sdk.search = sdk.query_dataset_in_querydsl  # type: ignore[attr-defined]

    def _count(dataset: str) -> Dict[str, Any]:
        url = f"{sdk.endpoint}/{dataset}/_count"
        return sdk.request("GET", url)  # type: ignore[arg-type]

    sdk.count = _count  # type: ignore[attr-defined]
    sdk._session = sdk.session  # type: ignore[attr-defined]
    return sdk


@pytest.fixture
def access_key():
    """Test access key"""
    return "test_access_key"


@pytest.fixture
def secret_key():
    """Test secret key"""
    return "test_secret_key"


@pytest.fixture
def endpoint():
    """Test endpoint"""
    return "https://api.test.infino.ws"


@pytest.fixture
def retry_config():
    """Test retry configuration"""
    config = RetryConfig()
    config.max_retries = 2
    config.initial_interval = 100
    config.max_interval = 500
    return config


@pytest.fixture
def mock_response():
    """Create a mock HTTP response"""
    import json as json_lib

    def _mock_response(status=200, json_data=None, text=""):
        response = Mock()
        response.status_code = status

        if json_data:
            response.text = json_lib.dumps(json_data)
        else:
            response.text = text

        return response

    return _mock_response


@pytest.fixture
def mock_requests():
    """Create a mock requests module for testing"""
    with patch("infino_sdk.lib.requests") as mock_req:
        yield mock_req


@pytest.fixture
def sdk_with_mock_session():
    """Create SDK with mocked session for testing"""
    with patch("infino_sdk.lib.requests") as mock_requests:
        # Set up RequestException as a proper exception class that doesn't catch everything
        class MockRequestException(Exception):
            pass

        mock_requests.RequestException = MockRequestException

        # Create SDK with minimal retry config to avoid hanging
        retry_config = RetryConfig()
        retry_config.max_retries = 1
        retry_config.initial_interval = 10
        retry_config.max_interval = 10

        sdk = InfinoSDK(
            "test_access", "test_secret", "https://test.infino.ws", retry_config
        )
        sdk = _attach_sdk_helpers(sdk)

        mock_session = MagicMock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"success": true}'
        mock_session.request.return_value = mock_response

        sdk.session = mock_session
        sdk._session = sdk.session  # type: ignore[attr-defined]

        yield sdk


@pytest.fixture
def mock_sdk():
    """Create a mock SDK instance for testing (alias for sdk_with_mock_session)"""
    with patch("infino_sdk.lib.requests") as mock_requests:
        # Set up RequestException as a proper exception class that doesn't catch everything
        class MockRequestException(Exception):
            pass

        mock_requests.RequestException = MockRequestException

        # Create SDK with minimal retry config to avoid hanging
        retry_config = RetryConfig()
        retry_config.max_retries = 1
        retry_config.initial_interval = 10
        retry_config.max_interval = 10

        sdk = InfinoSDK(
            "test_access", "test_secret", "https://test.infino.ws", retry_config
        )
        sdk = _attach_sdk_helpers(sdk)

        mock_session = MagicMock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"success": true}'
        mock_session.request.return_value = mock_response

        sdk.session = mock_session
        sdk._session = sdk.session  # type: ignore[attr-defined]

        yield sdk, mock_requests


@pytest.fixture
def sample_search_response():
    """Sample search response"""
    return {
        "took": 5,
        "timed_out": False,
        "hits": {
            "total": {"value": 100, "relation": "eq"},
            "max_score": 1.0,
            "hits": [
                {
                    "_index": "test_index",
                    "_id": "1",
                    "_score": 1.0,
                    "_source": {"name": "Test Document", "value": 42},
                },
                {
                    "_index": "test_index",
                    "_id": "2",
                    "_score": 0.9,
                    "_source": {"name": "Another Document", "value": 24},
                },
            ],
        },
    }


@pytest.fixture
def sample_index_response():
    """Sample index info response"""
    return {
        "test_index": {
            "aliases": {},
            "mappings": {
                "properties": {"name": {"type": "text"}, "value": {"type": "integer"}}
            },
            "settings": {"index": {"number_of_shards": "1", "number_of_replicas": "1"}},
        }
    }


@pytest.fixture
def sample_bulk_response():
    """Sample bulk operation response"""
    return {
        "took": 30,
        "errors": False,
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
                    "_version": 1,
                    "result": "created",
                    "status": 201,
                }
            },
        ],
    }


@pytest.fixture
def sample_user_response():
    """Sample user info response"""
    return {"test_user": {"Version": "2025-01-01", "Roles": ["admin", "analyst"]}}


@pytest.fixture
def sample_sql_response():
    """Sample SQL query response"""
    return {
        "schema": [
            {"name": "name", "type": "text"},
            {"name": "price", "type": "float"},
        ],
        "datarows": [["Product 1", 29.99], ["Product 2", 49.99]],
        "total": 2,
        "size": 2,
    }


@pytest.fixture
def sample_promql_instant_response():
    """Sample PromQL instant query response"""
    import time

    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {
                    "metric": {"__name__": "cpu_usage", "host": "server1"},
                    "value": [time.time(), "75.5"],
                }
            ],
        },
    }


@pytest.fixture
def sample_promql_range_response():
    """Sample PromQL range query response"""
    import time

    now = time.time()
    return {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {
                    "metric": {"__name__": "cpu_usage", "host": "server1"},
                    "values": [[now, "75.5"], [now + 60, "80.1"], [now + 120, "78.3"]],
                }
            ],
        },
    }
