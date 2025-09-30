"""
Pytest configuration and shared fixtures
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
from infino_sdk.lib import InfinoSDK, RetryConfig


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
    return "https://api.test.infino.ai"


@pytest.fixture
def retry_config():
    """Test retry configuration"""
    config = RetryConfig()
    config.max_retries = 2
    config.initial_interval = 100
    config.max_interval = 500
    return config


@pytest.fixture
async def sdk(access_key, secret_key, endpoint, retry_config):
    """Create SDK instance for testing"""
    sdk = InfinoSDK(
        access_key=access_key,
        secret_key=secret_key,
        endpoint=endpoint,
        retry_config=retry_config
    )
    await sdk._ensure_session()
    yield sdk
    await sdk.close()


@pytest.fixture
def mock_response():
    """Create a mock HTTP response"""
    def _mock_response(status=200, json_data=None, text=""):
        response = AsyncMock()
        response.status = status
        response.text = AsyncMock(return_value=text)
        
        if json_data:
            import json as json_module
            response.text = AsyncMock(return_value=json_module.dumps(json_data))
        
        return response
    
    return _mock_response


@pytest.fixture
def mock_session(mock_response):
    """Create a mock aiohttp session"""
    session = AsyncMock()
    
    # Default successful response
    response = mock_response(200, {"acknowledged": True})
    session.request.return_value.__aenter__.return_value = response
    
    return session


@pytest.fixture
async def sdk_with_mock_session(access_key, secret_key, endpoint, mock_session):
    """Create SDK with mocked session"""
    sdk = InfinoSDK(access_key, secret_key, endpoint)
    sdk.session = mock_session
    yield sdk
    # Don't close - session is mocked


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
                    "_source": {"name": "Test Document", "value": 42}
                },
                {
                    "_index": "test_index",
                    "_id": "2",
                    "_score": 0.9,
                    "_source": {"name": "Another Document", "value": 24}
                }
            ]
        }
    }


@pytest.fixture
def sample_index_response():
    """Sample index info response"""
    return {
        "test_index": {
            "aliases": {},
            "mappings": {
                "properties": {
                    "name": {"type": "text"},
                    "value": {"type": "integer"}
                }
            },
            "settings": {
                "index": {
                    "number_of_shards": "1",
                    "number_of_replicas": "1"
                }
            }
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
                    "status": 201
                }
            },
            {
                "index": {
                    "_index": "test_index",
                    "_id": "2",
                    "_version": 1,
                    "result": "created",
                    "status": 201
                }
            }
        ]
    }


@pytest.fixture
def sample_user_response():
    """Sample user info response"""
    return {
        "test_user": {
            "hash": "",
            "backend_roles": ["admin"],
            "attributes": {
                "department": "engineering"
            },
            "opendistro_security_roles": ["all_access"]
        }
    }


@pytest.fixture
def sample_sql_response():
    """Sample SQL query response"""
    return {
        "schema": [
            {"name": "name", "type": "text"},
            {"name": "price", "type": "float"}
        ],
        "datarows": [
            ["Product 1", 29.99],
            ["Product 2", 49.99]
        ],
        "total": 2,
        "size": 2
    }
