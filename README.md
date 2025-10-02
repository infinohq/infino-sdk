# Infino Python SDK

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Official Python SDK for [Infino](https://infino.ai), providing seamless access to search, analytics, ML, and AI capabilities with AWS SigV4 authentication.

This API is derived from OpenSearch, so most tools that work with OpenSearch should work with Infino.

## Installation

### From Source (Recommended until published to PyPI)

```bash
# Clone the repository
git clone https://github.com/infinohq/infino-sdk.git
cd infino-sdk

# Install the package
pip install -e .
```

### From GitHub (Direct)

```bash
pip install git+https://github.com/infinohq/infino-sdk.git
```

### From PyPI (Coming Soon)

```bash
pip install infino-sdk
```

## Quick Start

```python
from infino_sdk import InfinoSDK

# Create SDK instance with your credentials
sdk = InfinoSDK(
    access_key="your_access_key",
    secret_key="your_secret_key",
    endpoint="https://api.infino.ws"
)

# Check connection
info = sdk.ping()
print(f"Connected: {info}")

# Execute a search
results = sdk.search("my_index", '{"query": {"match_all": {}}}')
print(f"Found {len(results.get('hits', {}).get('hits', []))} documents")
```

## Getting Your Credentials

1. Sign up at [app.infino.ws](https://app.infino.ws)
2. Create a new account (accounts can only be created through the UI)
3. Navigate to Settings → API Keys
4. Generate your `access_key` and `secret_key`

## Documentation

### Table of Contents

- [Basic Usage](#basic-usage)
- [Search & Query](#search--query)
- [Bulk Operations](#bulk-operations)
- [Permissions Management](#security-management)
- [WebSocket Connections](#websocket-connections)
- [Error Handling](#error-handling)
- [Advanced Configuration](#advanced-configuration)

### Basic Usage

#### Creating an SDK Instance

```python
from infino_sdk import InfinoSDK

# Create instance and call synchronously
sdk = InfinoSDK(access_key, secret_key, endpoint)
sdk.ping()
```

#### Index Management

```python
sdk = InfinoSDK(access_key, secret_key, endpoint)

# Create index
sdk.create_index("products")

# Create index with custom mapping
mapping = {
    "mappings": {
        "properties": {
            "title": {"type": "text"},
            "price": {"type": "float"},
            "created_at": {"type": "date"}
        }
    }
}
sdk.create_index_with_mapping("products_v2", mapping)

# Get index info
info = sdk.get_index("products")

# List all indices
indices = sdk.get_cat_indices()

# Delete index
sdk.delete_index("old_products")
```

### Search & Query

#### OpenSearch Query DSL

```python
# Match all query
query = '{"query": {"match_all": {}}}'
results = sdk.search("products", query)

# Term query
query = '{"query": {"term": {"category": "electronics"}}}'
results = sdk.search("products", query)

# Complex query with aggregations
query = '''
{
  "query": {
    "bool": {
      "must": [{"range": {"price": {"gte": 10, "lte": 100}}}],
      "filter": [{"term": {"in_stock": true}}]
    }
  },
  "aggs": {
    "price_ranges": {
      "range": {
        "field": "price",
        "ranges": [
          {"to": 25},
          {"from": 25, "to": 50},
          {"from": 50}
        ]
      }
    }
  }
}
'''
results = sdk.search("products", query)
```

#### AI-Powered Search

```python
# Natural language search
results = sdk.search_ai("products", "find me affordable smartphones under $500")
```

#### SQL Queries

```python
# Execute SQL query
results = sdk.sql("SELECT * FROM products WHERE price > 100 ORDER BY created_at DESC LIMIT 10")

# With aggregations
results = sdk.sql("SELECT category, AVG(price) as avg_price FROM products GROUP BY category")
```

#### Document Operations

```python
# Get document by ID
doc = sdk.get_document("products", "product_123")

# Get document source only
source = sdk.get_source("products", "product_123")

# Check if document exists
exists = sdk.document_exists("products", "product_123")

# Count documents
count = sdk.count("products", '{"query": {"term": {"category": "electronics"}}}')

# Delete by query
result = sdk.delete_by_query("products", '{"query": {"range": {"created_at": {"lt": "2023-01-01"}}}}')
```

### Bulk Operations

#### Bulk Indexing

```python
# NDJSON format - each document is 2 lines: action + source
bulk_data = '''
{"index": {"_id": "1"}}
{"title": "Product 1", "price": 29.99, "category": "electronics"}
{"index": {"_id": "2"}}
{"title": "Product 2", "price": 49.99, "category": "home"}
{"update": {"_id": "3"}}
{"doc": {"price": 39.99}}
{"delete": {"_id": "4"}}
'''

result = sdk.bulk_ingest("products", bulk_data)
print(f"Indexed {result.get('items', [])} documents")
```

#### Metrics Ingestion

```python
# Prometheus-style metrics
metrics_data = 'http_requests_total{method="GET",status="200"} 1234 1609459200000'
sdk.metrics("metrics_index", metrics_data)
```

#### PromQL Queries

```python
# Instant query
result = sdk.prom_ql_query('http_requests_total{status="200"}')

# Range query
result = sdk.prom_ql_query_range(
    query='rate(http_requests_total[5m])',
    start=1609459200,
    end=1609545600,
    step=300
)

# Get labels
labels = sdk.prom_ql_labels()

# Get label values
values = sdk.prom_ql_label_values("method")
```

### Security Management

#### User Management

```python
# Create user
user_config = {
    "password": "SecureP@ssw0rd123",
    "backend_roles": ["admin"],
    "attributes": {
        "department": "engineering"
    }
}
await sdk.create_user("john_doe", user_config)

# Get user
user = await sdk.get_user("john_doe")

# Update user
await sdk.update_user("john_doe", {"password": "NewP@ssw0rd456"})

# List all users
users = await sdk.list_users()

# Delete user
await sdk.delete_user("john_doe")

# Rotate API keys
new_keys = await sdk.rotate_api_keys("john_doe")
print(f"New access key: {new_keys['access_key']}")
print(f"New secret key: {new_keys['secret_key']}")
```

#### Role Management

```python
# Create role
role_config = {
    "cluster_permissions": ["cluster:admin/*"],
    "index_permissions": [
        {
            "index_patterns": ["products*"],
            "allowed_actions": ["read", "write", "indices:admin/create"]
        },
        {
            "index_patterns": ["logs*"],
            "allowed_actions": ["read"]
        }
    ]
}
await sdk.create_role("product_manager", role_config)

# Get role
role = await sdk.get_role("product_manager")

# Update role
await sdk.update_role("product_manager", {"cluster_permissions": ["cluster:monitor/*"]})

# List roles
roles = await sdk.list_roles()

# Delete role
await sdk.delete_role("product_manager")
```

#### Role Mapping

```python
# Map users to roles
mapping_config = {
    "users": ["john_doe", "jane_smith"],
    "backend_roles": ["developer"],
    "hosts": ["*.company.com"]
}
await sdk.create_role_mapping("dev_team_mapping", mapping_config)

# Get mapping
mapping = await sdk.get_role_mapping("dev_team_mapping")

# Update mapping
await sdk.update_role_mapping("dev_team_mapping", {"users": ["john_doe"]})

# List mappings
mappings = await sdk.list_role_mappings()

# Delete mapping
await sdk.delete_role_mapping("dev_team_mapping")
```

### Natural Language

```python
async with InfinoSDK(access_key, secret_key, endpoint) as sdk:
    # Connect to WebSocket endpoint (auth handled automatically)
    ws = await sdk.websocket_connect("/_conversation/ws")

    try:
        # Send a message
        await ws.send(json.dumps({
            "type": "query",
            "content": "What are my top products?"
        }))

        # Receive response
        async for message in ws:
            data = json.loads(message)
            print(f"Received: {data}")
            if data.get("type") == "complete":
                break
    finally:
        await ws.close()
```

### Error Handling

```python
from infino_sdk import InfinoSDK, InfinoError

async with InfinoSDK(access_key, secret_key, endpoint) as sdk:
    try:
        doc = await sdk.get_document("products", "missing_id")
    except InfinoError as e:
        # Check error type
        if e.error_type == InfinoError.Type.REQUEST:
            if e.status_code() == 404:
                print("Document not found")
            elif e.status_code() == 403:
                print("Access denied")
            elif e.status_code() == 401:
                print("Authentication failed")
            else:
                print(f"Request error: {e.message}")
        elif e.error_type == InfinoError.Type.NETWORK:
            print(f"Network error: {e.message}")
        elif e.error_type == InfinoError.Type.TIMEOUT:
            print("Request timed out")
        elif e.error_type == InfinoError.Type.RATE_LIMIT:
            print("Rate limit exceeded")
```

### Advanced Configuration

#### Custom Retry Configuration

```python
from infino_sdk import InfinoSDK, RetryConfig

# Configure custom retry behavior
retry_config = RetryConfig()
retry_config.initial_interval = 500  # Start with 500ms delay
retry_config.max_interval = 30000    # Max 30 seconds between retries
retry_config.max_elapsed_time = 180000  # Give up after 3 minutes
retry_config.max_retries = 5         # Try up to 5 times

sdk = InfinoSDK(
    access_key=access_key,
    secret_key=secret_key,
    endpoint=endpoint,
    retry_config=retry_config
)
```

#### Logging

```python
import logging

# Enable SDK logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("infino_sdk")
logger.setLevel(logging.DEBUG)

# SDK will log all requests and responses
async with InfinoSDK(access_key, secret_key, endpoint) as sdk:
    await sdk.ping()  # Logs will show request details
```

## Examples

See the [examples/](examples/) directory for complete working examples:

- [**basic_search.py**](examples/basic_search.py) - Simple search operations
- [**bulk_indexing.py**](examples/bulk_indexing.py) - Bulk data ingestion
- [**user_management.py**](examples/user_management.py) - Security and access control
- [**websocket_chat.py**](examples/websocket_chat.py) - Real-time WebSocket communication
- [**sql_analytics.py**](examples/sql_analytics.py) - SQL query examples
- [**error_handling.py**](examples/error_handling.py) - Robust error handling patterns

## API Reference

Full API documentation is available in the [API Reference](docs/api-reference.md).

## Requirements

- Python 3.8 or higher
- aiohttp >= 3.8.0
- websockets >= 10.0
- backoff >= 2.0.0

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.

```bash
# Clone repository
git clone https://github.com/infinohq/infino-sdk-python.git
cd infino-sdk-python

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Run linter
flake8 infino_sdk tests

# Check types
mypy infino_sdk
```

## Support

- 📧 Email: support@infino.ai
- 💬 Discord: [discord.gg/infino](https://discord.gg/infino)
- 📖 Documentation: [docs.infino.ai](https://docs.infino.ai)
- 🐛 Issues: [GitHub Issues](https://github.com/infinohq/infino-sdk-python/issues)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.