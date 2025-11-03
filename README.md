# Infino Python SDK

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Official Python SDK for [Infino](https://infino.ai) - the unification layer for your data stack.

**Infino** provides a single gateway to your data stack. Query Elasticsearch, OpenSearch, Snowflake, and 50+ sources in natural language, SQL, QueryDSL, or PromQL. Bring diverse data sources together for deeper analysis—no ETL required. Control access via fine-grained RBAC. All through one unified API. 

**Built for**:
- **Connect**: Access 50+ data sources without data movement
- **Query**: Natural language, SQL, Query DSL, and PromQL across all sources  
- **Correlate**: Pull together data from different sources for cross-source correlation
- **Govern**: Fine-grained RBAC for your entire data stack

## Installation

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

# Query a dataset
results = sdk.query_dataset_in_querydsl("my-dataset", '{"query": {"match_all": {}}}')
print(f"Found {len(results.get('hits', {}).get('hits', []))} records")
```

## Getting Your Credentials

1. Sign up at [app.infino.ws](https://app.infino.ws)
2. Create a new account (accounts can only be created through the UI)
3. Navigate to Settings → API Keys
4. Generate your `access_key` and `secret_key`

## Documentation

### Table of Contents

- [Quick Start](#quick-start)
- [Connect – Access Data Sources](#connect--access-data-sources)
- [Query – Ask Questions](#query--ask-questions)
- [Analyze – Cross-Source Operations](#analyze--cross-source-operations)
- [Govern – Security & Access Control](#govern--security--access-control)
- [Error Handling](#error-handling)
- [Advanced Configuration](#advanced-configuration)

## Connect – Access Data Sources

Connect to data sources and query them in place.

### Create Connections

```python
from infino_sdk import InfinoSDK

sdk = InfinoSDK(access_key, secret_key, endpoint)

# Create connection to Elasticsearch
connection_config = {
    "connector_id": "elasticsearch",
    "name": "Production ES Cluster",
    "config": {
        "host": "https://es-cluster.example.com:9200",
        "username": "elastic",
        "password": "secret"
    }
}
connection = sdk.create_connection("elasticsearch", connection_config)
print(f"Created connection: {connection['connection_id']}")

# List all connections
connections = sdk.get_connections()

# Get connection status
status = sdk.get_connection("conn_abc123")
```

### Query Connected Sources

```python
# Query Elasticsearch (via QueryDSL)
results = sdk.query_source(
    connection_id="conn_elasticsearch_prod",
    dataset="external_logs", 
    query='{"query": {"match_all": {}}}'
)

# Query Snowflake (via SQL)
results = sdk.query_source(
    connection_id="conn_snowflake_prod",
    dataset="sales_data",
    query="SELECT * FROM sales_data WHERE region='US' LIMIT 10"
)
```

**No ETL**: Data stays in your sources. Infino queries it where it lives.

## Query – Ask Questions

Query any connected source or dataset with multiple interfaces.

### Natural Language (Fino AI)

```python
import asyncio
import json

async def query_with_fino():
    sdk = InfinoSDK(access_key, secret_key, endpoint)
    
    # Connect to Fino WebSocket
    ws = await sdk.websocket_connect("/_conversation/ws")
    
    try:
        # Send your question
        await ws.send(json.dumps({
            "type": "query",
            "content": "What are the top 5 products by revenue?"
        }))
        
        # Receive AI response
        async for message in ws:
            data = json.loads(message)
            print(f"Fino: {data.get('content', '')}")
            if data.get("type") == "complete":
                break
    finally:
        await ws.close()
        sdk.close()

# Run async
asyncio.run(query_with_fino())
```

### Manage Conversation Threads

```python
# Create and manage Fino conversation threads
sdk = InfinoSDK(access_key, secret_key, endpoint)

# List existing threads
threads = sdk.list_threads()

# Create a new thread with optional metadata
thread = sdk.create_thread({
    "name": "Sales Analysis",
    "workflow_name": "alpha_v1"
})

# Add a message to the thread
sdk.add_thread_message(thread["id"], {
    "content": {
        "user_query": "What are the top 5 regions by revenue?"
    },
    "role": "user"
})

# Send a message using the simplified API (thread_id in payload)
sdk.send_message({
    "thread_id": thread["id"],
    "content": {
        "user_query": "Show me week-over-week trends"
    },
    "role": "user"
})

# Clean up when finished
sdk.clear_thread_messages(thread["id"])
sdk.delete_thread(thread["id"])
```

### SQL Queries

```python
# Query a dataset with SQL
results = sdk.query_dataset_in_sql("SELECT * FROM products WHERE price > 100 LIMIT 10")

# With aggregations
results = sdk.query_dataset_in_sql("SELECT category, AVG(price) FROM products GROUP BY category")
```

### Query DSL

```python
# Simple query on a dataset
query = '{"query": {"match_all": {}}}'
results = sdk.query_dataset_in_querydsl("products", query)

# Complex query with filters
query = '''
{
  "query": {
    "bool": {
      "must": [{"range": {"price": {"gte": 10, "lte": 100}}}],
      "filter": [{"term": {"in_stock": true}}]
    }
  }
}
'''
results = sdk.query_dataset_in_querydsl("products", query)

# Query data source
results = sdk.query_source(
    connection_id="conn_opensearch",
    dataset="dataset",
    query=query
)
```

### PromQL (Time-Series)

```python
# Instant PromQL query
result = sdk.query_dataset_in_promql(
    'http_requests_total{status="200"}',
    dataset="metrics_example",
)

# Range PromQL query
result = sdk.query_dataset_in_promql_range(
    query='rate(http_requests_total[5m])',
    start=1609459200,
    end=1609545600,
    step=300,
    dataset="metrics_example",
)
```

## Correlate – Cross-Source Operations

Use datasets to pull together data from different sources for correlation and analysis without schemas.

### When to Use Datasets

- **Cross-Source Joins**: Correlate data from multiple data sources
- **Unified Analysis**: Ask deeper questions across silos
- **Staging**: Test queries before running in production
- **Temporary Storage**: Hold intermediate results for complex workflows

### Create Datasets

```python
# Create a dataset for staging
sdk.create_dataset("staging-analysis-2024")
```

### Upload Data

```python
# Upload records to a dataset for correlation
bulk_data = '''
{"index": {"_id": "1"}}
{"product_id": "A123", "revenue": 15000, "@timestamp": "2024-10-15"}
{"index": {"_id": "2"}}
{"product_id": "B456", "revenue": 23000, "@timestamp": "2024-10-15"}
'''

sdk.upload_json_to_dataset("sales-correlation", bulk_data)
```

### Manage Datasets

```python
# Get dataset metadata
metadata = sdk.get_dataset_metadata("sales-correlation")

# List all datasets
datasets = sdk.get_datasets()

# Delete dataset
sdk.delete_dataset("old-staging-2023")
```

### Record Operations

```python
# Get a record
record = sdk.get_record("sales-correlation", "prod_123")

# Delete records
sdk.delete_records("sales-correlation", '{"query": {"range": {"@timestamp": {"lt": "2024-01-01"}}}}')
```

### Dataset Enrichment

```python
# Configure enrichment for a dataset
import json

enrich_policy = json.dumps({
    "enrich_policy": {
        "match_field": "user_id",
        "enrich_fields": ["email", "name", "department"]
    }
})

sdk.enrich_dataset("sales-correlation", enrich_policy)
```

## Govern – Security & Access Control

Control access to your entire data stack with centralized governance for both humans and agents.

### Complete Workflow Example

```python
from infino_sdk import InfinoSDK

sdk = InfinoSDK(access_key, secret_key, endpoint)

# Step 1: Create a role with specific permissions
role_config = """
Version: 2025-01-01
Permissions:
  - ResourceType: record
    Actions: [read]
    Resources: ["logs-*", "metrics-*"]
  
  - ResourceType: metadata
    Actions: [read]
    Resources: ["*"]
"""

sdk.create_role("readonly-analyst", role_config)

# Step 2: Create user and assign the role
user_config = """
Version: 2025-01-01
Password: SecureP@ssw0rd123!
Roles:
  - readonly-analyst
"""

sdk.create_user("analytics-agent", user_config)

# Step 3: Rotate API keys when needed
new_keys = sdk.rotate_keys()
print(f"New access key: {new_keys['access_key']}")
```

### User Management

```python
# List all users
users = sdk.list_users()

# Get specific user
user = sdk.get_user("analytics-agent")

# Update user password or roles
updated_config = """
Version: 2025-01-01
Password: NewP@ssw0rd456!
Roles:
  - readonly-analyst
  - data-viewer
"""
sdk.update_user("analytics-agent", updated_config)

# Delete user
sdk.delete_user("analytics-agent")
```

### Role Management

```python
# Create role with field-level security
role_with_masking = """
Version: 2025-01-01
Permissions:
  - ResourceType: record
    Actions: [read]
    Resources: ["users-*"]
    Fields:
      Allow: ["id", "name", "email"]
      Mask:
        email: redact
        ssn: remove
      Deny:
        - password
        - api_key
"""
sdk.create_role("privacy-compliant-analyst", role_with_masking)

# Get role details
role = sdk.get_role("readonly-analyst")

# Delete role
sdk.delete_role("old-role")
```

### Resource Types & Actions

Permissions use universal terminology that works across SQL, NoSQL, logs, and metrics:

| ResourceType | Actions | What It Controls |
|--------------|---------|------------------|
| `metadata` | `read` | View schemas, mappings, list datasets |
| `dataset` | `create`, `delete` | Create/delete datasets |
| `record` | `read`, `write` | Query/insert/update/delete records |
| `field` | N/A | Controlled via `Fields` in record permissions |

**Centralized Governance**: Apply consistent policies across all connected sources for both humans and agents.

## Error Handling

```python
from infino_sdk import InfinoSDK, InfinoError

async with InfinoSDK(access_key, secret_key, endpoint) as sdk:
    try:
        record = sdk.get_record("products", "missing_id")
    except InfinoError as e:
        if e.error_type == InfinoError.Type.REQUEST:
            if e.status_code() == 404:
                print("Record not found")
            elif e.status_code() == 403:
                print("Access denied - check user permissions")
            elif e.status_code() == 401:
                print("Authentication failed")
        elif e.error_type == InfinoError.Type.NETWORK:
            print(f"Network error: {e.message}")
```

## Advanced Configuration

### Custom Retry Configuration

```python
from infino_sdk import InfinoSDK, RetryConfig

retry_config = RetryConfig()
retry_config.initial_interval = 500
retry_config.max_retries = 5

sdk = InfinoSDK(
    access_key=access_key,
    secret_key=secret_key,
    endpoint=endpoint,
    retry_config=retry_config
)
```

### Logging

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("infino_sdk")
logger.setLevel(logging.DEBUG)

# SDK logs all requests
sdk = InfinoSDK(access_key, secret_key, endpoint)
sdk.ping()
```

## Examples

Complete working examples organized by workflow:

### Connect Examples
- [**basic_query.py**](examples/basic_query.py) - Query data sources with Query DSL

### Query Examples
- [**sql_analytics.py**](examples/sql_analytics.py) - SQL queries across sources
- [**fino_nl.py**](examples/fino_nl.py) - Natural language with Fino AI
- [**promql_metrics.py**](examples/promql_metrics.py) - PromQL time-series queries

### Correlate Examples
- [**upload_json.py**](examples/upload_json.py) - Pull data together for cross-source analysis

### Govern Examples
- [**user_management.py**](examples/user_management.py) - Centralized access control

### Utilities
- [**error_handling.py**](examples/error_handling.py) - Robust error handling patterns

## API Reference

Full method documentation available in code docstrings and [docs.infino.ai](https://docs.infino.ai).

## Requirements

- Python 3.8 or higher
- aiohttp >= 3.8.0
- websockets >= 10.0
- backoff >= 2.0.0

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.

```bash
# Clone repository
git clone https://github.com/infinohq/infino-sdk.git
cd infino-sdk

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
- 📖 Documentation: [docs.infino.ai](https://docs.infino.ai)
- 🐛 Issues: [GitHub Issues](https://github.com/infinohq/infino-sdk/issues)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.
