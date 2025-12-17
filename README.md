# Infino Python SDK

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Official Python SDK for [Infino](https://infino.ai) - the context engine for your data stack.

**Infino** provides an intelligent unification layer for your data stack. Query Elasticsearch, OpenSearch, Snowflake, and other data sources in natural language, SQL, QueryDSL, or PromQL. Bring diverse data sources together for deeper analysis—no ETL required. Control access via fine-grained RBAC. All through one unified API. 

**Built for**:
- **Connect**: Access your data sources without data movement
- **Query**: Natural language, SQL, Query DSL, and PromQL across all sources
- **Correlate**: Pull together data from different sources for cross-source correlation
- **Govern**: Fine-grained RBAC for your entire data stack

## Table of Contents

- [Quick Start](#quick-start)
  - [Installation](#installation)
  - [Getting Your Credentials](#getting-your-credentials)
  - [Basic Usage](#basic-usage)
- [API Reference](#api-reference)
- [Connect – Access Data Sources](#connect--access-data-sources)
  - [Discover Available Sources](#discover-available-sources)
  - [Manage Connections](#manage-connections)
  - [Query Connected Sources](#query-connected-sources)
  - [File Upload](#file-upload)
  - [Import Jobs](#import-jobs)
- [Query – Ask Questions](#query--ask-questions)
  - [Natural Language (Fino AI)](#natural-language-fino-ai)
  - [Manage Conversation Threads](#manage-conversation-threads)
  - [SQL (relational queries)](#sql-queries)
  - [Query DSL (text search)](#query-dsl)
  - [PromQL (time-series)](#promql-time-series)
- [Correlate – Cross-Source Operations](#correlate--cross-source-operations)
  - [When to Use Datasets](#when-to-use-datasets)
  - [Create Datasets](#create-datasets)
  - [Upload Data](#upload-data)
  - [Manage Datasets](#manage-datasets)
  - [Record Operations](#record-operations)
  - [Dataset Enrichment](#dataset-enrichment)
- [Govern – Security & Access Control](#govern--security--access-control)
  - [Complete Workflow Example](#complete-workflow-example)
  - [User Management](#user-management)
  - [Role Management](#role-management)
  - [Resource Types & Actions](#resource-types--actions)
- [Error Handling](#error-handling)
- [Advanced Configuration](#advanced-configuration)
  - [SDK Initialization](#sdk-initialization)
  - [Context Manager Usage](#context-manager-usage)
  - [Custom Retry Configuration](#custom-retry-configuration)
  - [Logging](#logging)
- [Examples](#examples)
- [Development](#development)
- [Support](#support)

## Quick Start

### Installation

```bash
pip install infino-sdk
```

### Getting Your Credentials

1. Sign up at [app.infino.ws](https://app.infino.ws)
2. Create a new account (accounts can only be created through the UI)
3. Navigate to Settings → API Keys
4. Generate your `access_key` and `secret_key`

### Basic Usage

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

## API Reference

Complete reference of SDK methods organized by category. Click any method to jump to its code example.

### Initialization & Utilities (5 methods)

| Method | Description |
|--------|-------------|
| [`InfinoSDK(access_key, secret_key, endpoint, retry_config=None)`](#sdk-initialization) | Initialize SDK instance |
| [`InfinoSDK.new(access_key, secret_key, endpoint)`](#sdk-initialization) | Alternative constructor |
| [`InfinoSDK.new_with_retry(access_key, secret_key, endpoint, retry_config)`](#sdk-initialization) | Constructor with retry config |
| [`ping()`](#quick-start) | Health check endpoint |
| [`close()`](#context-manager-usage) | Close HTTP session |

**Context Manager**: SDK supports `with` statement for automatic resource cleanup ([see usage](#context-manager-usage)).

### Datasets (11 methods)

| Method | Description |
|--------|-------------|
| [`create_dataset(dataset)`](#create-datasets) | Create empty dataset |
| [`delete_dataset(dataset)`](#manage-datasets) | Delete dataset |
| [`get_datasets()`](#manage-datasets) | List all datasets |
| [`get_dataset_metadata(dataset)`](#manage-datasets) | Get dataset metadata (count, size, etc.) |
| [`get_dataset_schema(dataset)`](#manage-datasets) | Get dataset field mappings |
| [`upload_json_to_dataset(dataset, payload)`](#upload-data) | Upload NDJSON bulk data |
| [`upsert_to_dataset(query)`](#upload-data) | Upsert via SQL INSERT/UPDATE |
| [`upload_metrics_to_dataset(dataset, payload)`](#upload-data) | Upload Prometheus metrics |
| [`get_record(dataset, record_id)`](#record-operations) | Get single record by ID |
| [`delete_records(dataset, query)`](#record-operations) | Delete records matching query |
| [`enrich_dataset(dataset, policy)`](#dataset-enrichment) | Configure dataset enrichment |

### Query Methods (5 methods)

| Method | Description |
|--------|-------------|
| [`query_dataset_in_querydsl(dataset, query)`](#query-dsl) | Query using Elasticsearch/OpenSearch DSL |
| [`query_dataset_in_sql(query)`](#sql-queries) | Query using SQL (supports joins) |
| [`query_dataset_in_promql(query, dataset=None)`](#promql-time-series) | Instant PromQL query |
| [`query_dataset_in_promql_range(query, start, end, step, dataset=None)`](#promql-time-series) | Range PromQL query |
| [`query_source(connection_id, dataset, query)`](#query-connected-sources) | Query connected source in native DSL |

### Fino AI (9 methods)

| Method | Description |
|--------|-------------|
| [`websocket_connect(path, headers=None)`](#natural-language-fino-ai) | Connect to WebSocket for streaming |
| [`list_threads()`](#manage-conversation-threads) | List all conversation threads |
| [`create_thread(config)`](#manage-conversation-threads) | Create new thread |
| [`get_thread(thread_id)`](#manage-conversation-threads) | Get thread details |
| [`update_thread(thread_id, config)`](#manage-conversation-threads) | Update thread metadata |
| [`delete_thread(thread_id)`](#manage-conversation-threads) | Delete thread |
| [`add_thread_message(thread_id, message)`](#manage-conversation-threads) | Add message to thread |
| [`clear_thread_messages(thread_id)`](#manage-conversation-threads) | Clear all thread messages |
| [`send_message(payload)`](#manage-conversation-threads) | Send message (simplified API) |

### Connections (12 methods)

| Method | Description |
|--------|-------------|
| [`get_sources()`](#discover-available-sources) | List available data source types |
| [`get_connections()`](#manage-connections) | List active connections |
| [`create_connection(source_type, config)`](#manage-connections) | Create connection |
| [`get_connection(connection_id)`](#manage-connections) | Get connection status |
| [`update_connection(connection_id, config)`](#manage-connections) | Update connection |
| [`delete_connection(connection_id)`](#manage-connections) | Delete connection |
| [`get_source_metadata(connection_id, dataset)`](#query-connected-sources) | Get metadata from source |
| [`upload_file(dataset, file_path, format, ...)`](#file-upload) | Upload file (JSON, JSONL, CSV) |
| [`get_connector_job_status(run_id)`](#file-upload) | Get async job status |
| [`create_import_job(source_type, config)`](#import-jobs) | Create import job |
| [`get_import_jobs()`](#import-jobs) | List import jobs |
| [`delete_import_job(job_id)`](#import-jobs) | Delete import job |

### RBAC & Governance (11 methods)

| Method | Description |
|--------|-------------|
| [`create_user(name, config)`](#user-management) | Create user (YAML or JSON) |
| [`get_user(name)`](#user-management) | Get user details |
| [`update_user(name, config)`](#user-management) | Update user |
| [`delete_user(name)`](#user-management) | Delete user |
| [`list_users()`](#user-management) | List all users |
| [`create_role(name, config)`](#role-management) | Create role (YAML or JSON) |
| [`get_role(name)`](#role-management) | Get role details |
| [`update_role(name, config)`](#role-management) | Update role permissions |
| [`delete_role(name)`](#role-management) | Delete role |
| [`list_roles()`](#role-management) | List all roles |
| [`rotate_keys(username)`](#complete-workflow-example) | Rotate API keys for user |

---

## Connect – Access Data Sources

Connect to data sources and query them in place without data movement.

### Discover Available Sources

```python
from infino_sdk import InfinoSDK

sdk = InfinoSDK(access_key, secret_key, endpoint)

# Get list of all available data source types
sources = sdk.get_sources()
for source in sources:
    print(f"{source['name']}: {source['description']}")
```

### Manage Connections

```python
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

# List all active connections
connections = sdk.get_connections()

# Get connection status
status = sdk.get_connection("conn_abc123")
print(f"Status: {status['status']}")

# Update connection configuration
updated_config = {
    "name": "Production ES Cluster - Updated",
    "config": {
        "host": "https://new-es-cluster.example.com:9200",
        "username": "elastic",
        "password": "new_secret"
    }
}
sdk.update_connection("conn_abc123", updated_config)

# Delete connection
sdk.delete_connection("conn_old_123")
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

# Get metadata from a connected source
metadata = sdk.get_source_metadata("conn_elasticsearch_prod", "logs-2024")
print(f"Fields: {metadata['mappings']}")
```

### File Upload

Upload files directly to datasets without setting up connections. Supports JSON, JSONL, and CSV formats.

```python
from infino_sdk import InfinoSDK

sdk = InfinoSDK(access_key, secret_key, endpoint)

# Upload a JSON file (synchronous - waits for completion)
result = sdk.upload_file(
    dataset="my-dataset",
    file_path="data.json",
    format="json"  # or "jsonl", "csv", "auto"
)
print(f"Uploaded {result['stats']['documents_processed']} documents")

# Upload a CSV file
result = sdk.upload_file("sales-data", "quarterly_sales.csv", format="csv")

# Upload with async mode (for large files)
result = sdk.upload_file(
    dataset="large-dataset",
    file_path="big_data.jsonl",
    format="jsonl",
    async_mode=True  # Returns immediately with run_id
)
print(f"Job submitted: {result['run_id']}")

# Poll for completion
import time
while True:
    status = sdk.get_connector_job_status(result['run_id'])
    print(f"Status: {status['status']}")
    if status['status'] in ('completed', 'failed'):
        if status['status'] == 'completed':
            print(f"Processed {status['stats']['documents_processed']} docs")
        break
    time.sleep(2)
```

**Parameters:**
- `dataset`: Target dataset name
- `file_path`: Path to the file to upload
- `format`: File format - `"json"`, `"jsonl"`, `"csv"`, or `"auto"` (default: auto-detect)
- `batch_size`: Documents per batch (default: 1000)
- `async_mode`: If True, returns immediately with `run_id` for polling (default: False)

### Import Jobs

Import data from connected sources into datasets for correlation.

```python
# Create import job to bring data from Snowflake into a dataset
import_config = {
    "connection_id": "conn_snowflake_prod",
    "source_dataset": "sales_data",
    "target_dataset": "sales-correlation",
    "query": "SELECT * FROM sales_data WHERE date >= '2024-01-01'",
    "schedule": "0 2 * * *"  # Daily at 2 AM
}
job = sdk.create_import_job("snowflake", import_config)
print(f"Import job created: {job['job_id']}")

# List all import jobs
jobs = sdk.get_import_jobs()
for job in jobs:
    print(f"Job {job['job_id']}: {job['status']}")

# Delete import job
sdk.delete_import_job("job_abc123")
```

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
print(f"Found {len(threads)} threads")

# Create a new thread with optional metadata
thread = sdk.create_thread({
    "name": "Sales Analysis",
    "workflow_name": "alpha_v1"
})
print(f"Created thread: {thread['id']}")

# Get thread details
thread_info = sdk.get_thread(thread["id"])
print(f"Thread name: {thread_info['name']}")

# Update thread metadata
sdk.update_thread(thread["id"], {
    "name": "Q4 Sales Analysis - Updated",
    "metadata": {
        "department": "finance",
        "priority": "high"
    }
})

# Add a message to the thread
sdk.add_thread_message(thread["id"], {
    "content": {
        "user_query": "What are the top 5 regions by revenue?"
    },
    "role": "user"
})

# Send a message using the simplified API (thread_id in payload)
response = sdk.send_message({
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
# Upload JSON records to a dataset (NDJSON format)
bulk_data = '''
{"index": {"_id": "1"}}
{"product_id": "A123", "revenue": 15000, "@timestamp": "2024-10-15"}
{"index": {"_id": "2"}}
{"product_id": "B456", "revenue": 23000, "@timestamp": "2024-10-15"}
'''
sdk.upload_json_to_dataset("sales-correlation", bulk_data)

# Upload via SQL upsert (INSERT or UPDATE)
sql_upsert = """
    INSERT INTO sales_correlation (_id, product_id, revenue, timestamp)
    VALUES ('3', 'C789', 30000, '2024-10-15')
    ON CONFLICT (_id) DO UPDATE SET revenue = 30000
"""
sdk.upsert_to_dataset(sql_upsert)

# Upload Prometheus metrics to a dataset
metrics_data = '''
# TYPE http_requests_total counter
http_requests_total{method="GET",status="200"} 1234 1609459200000
http_requests_total{method="POST",status="201"} 567 1609459200000
'''
sdk.upload_metrics_to_dataset("metrics-correlation", metrics_data)
```

### Manage Datasets

```python
# Get dataset metadata
metadata = sdk.get_dataset_metadata("sales-correlation")
print(f"Document count: {metadata['count']}")

# Get dataset schema
schema = sdk.get_dataset_schema("sales-correlation")
print(f"Fields: {schema['mappings']}")

# List all datasets
datasets = sdk.get_datasets()
for dataset in datasets:
    print(f"Dataset: {dataset['name']}")

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

# List all roles
roles = sdk.list_roles()
for role in roles:
    print(f"Role: {role['name']}")

# Get role details
role = sdk.get_role("readonly-analyst")
print(f"Permissions: {role['permissions']}")

# Update role permissions
updated_role = """
Version: 2025-01-01
Permissions:
  - ResourceType: record
    Actions: [read, write]
    Resources: ["logs-*", "metrics-*"]
"""
sdk.update_role("readonly-analyst", updated_role)

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

### SDK Initialization

```python
from infino_sdk import InfinoSDK, RetryConfig

# Standard initialization
sdk = InfinoSDK(
    access_key="your_access_key",
    secret_key="your_secret_key",
    endpoint="https://api.infino.ws"
)

# Using class methods (alternative constructors)
sdk = InfinoSDK.new(access_key, secret_key, endpoint)

# With custom retry configuration
retry_config = RetryConfig()
retry_config.initial_interval = 500
retry_config.max_retries = 5

sdk = InfinoSDK.new_with_retry(
    access_key,
    secret_key,
    endpoint,
    retry_config
)
```

### Context Manager Usage

```python
from infino_sdk import InfinoSDK

# Automatic resource cleanup with context manager
with InfinoSDK(access_key, secret_key, endpoint) as sdk:
    results = sdk.query_dataset_in_sql("SELECT * FROM products")
    print(f"Found {len(results)} records")
    # Session automatically closed on exit

# Manual resource management
sdk = InfinoSDK(access_key, secret_key, endpoint)
try:
    results = sdk.query_dataset_in_sql("SELECT * FROM products")
finally:
    sdk.close()  # Explicitly close session
```

### Custom Retry Configuration

```python
from infino_sdk import InfinoSDK, RetryConfig

retry_config = RetryConfig()
retry_config.initial_interval = 500      # milliseconds
retry_config.max_interval = 30000        # milliseconds
retry_config.max_retries = 5
retry_config.max_elapsed_time = 180000   # milliseconds

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

# SDK logs all requests and signing operations
sdk = InfinoSDK(access_key, secret_key, endpoint)
sdk.ping()
```

## Examples

Complete working examples organized by workflow:

### Connect Examples
- [**basic_query.py**](examples/basic_query.py) - Query data sources with Query DSL
- [**file_upload.py**](examples/file_upload.py) - Upload JSON, JSONL, and CSV files

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
