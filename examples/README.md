# Infino SDK Examples

This directory contains comprehensive examples demonstrating how to use the Infino Python SDK,
particularly for analysis from different data sources in your stack.

## Setup

1. Install the SDK:
```bash
pip install infino-sdk
```

2. Set your credentials as environment variables:
```bash
export INFINO_ACCESS_KEY="your_access_key"
export INFINO_SECRET_KEY="your_secret_key"
export INFINO_ENDPOINT="https://api.infino.ai"
```

## Examples

### [basic_query.py](basic_query.py)
**Basic search operations and queries**

Learn how to:
- Create datasets
- Execute different types of queries (match_all, term, range, bool)
- Count documents
- Use aggregations
- Sort and filter results

```bash
python examples/basic_query.py
```

### [file_upload.py](file_upload.py)
**File upload operations (JSON, JSONL, CSV)**

Learn how to:
- Upload JSON files to datasets
- Upload JSONL (newline-delimited JSON) files
- Upload CSV files with automatic header parsing
- Use synchronous mode (wait for completion)
- Use asynchronous mode with job status polling
- Handle upload errors and statistics

```bash
python examples/file_upload.py
```

### [upload_json.py](upload_json.py)
**Bulk document operations**

Learn how to:
- Index large datasets efficiently
- Handle bulk operation results
- Update and delete documents in bulk
- Implement batch processing

```bash
python examples/upload_json.py
```

### [user_management.py](user_management.py)
**Security and access control**

Learn how to:
- Create and manage users
- Define custom roles and permissions
- Map users to roles
- Rotate API keys
- Manage security configuration

```bash
python examples/user_management.py
```

### [fino_websocket_chat.py](fino_websocket_chat.py)
**Natural Language Queries via WebSocket**

Learn how to:
- Create conversation threads via REST API
- Establish WebSocket connections with SigV4 authentication
- Send natural language queries and receive streaming AI responses
- Handle progress updates and final results
- Implement multi-turn conversations with context
- Build interactive chat sessions

```bash
python examples/fino_websocket_chat.py
```

### [sql_analytics.py](sql_analytics.py)
**SQL queries and analytics**

Learn how to:
- Execute SQL queries
- Use aggregations and GROUP BY
- Implement window functions
- Work with time-series data
- Use subqueries and CASE statements

```bash
python examples/sql_analytics.py
```

### [promql_metrics.py](promql_metrics.py)
**PromQL metrics and time-series queries**

Learn how to:
- Ingest metrics in Prometheus exposition format
- Execute PromQL instant queries
- Perform PromQL range queries for time-series data
- Use label selectors and filters
- Implement metric aggregations
- Calculate rates and perform arithmetic operations

```bash
python examples/promql_metrics.py
```

### [error_handling.py](error_handling.py)
**Robust error handling patterns**

Learn how to:
- Handle different error types (404, 401, 403, etc.)
- Implement retry strategies
- Use graceful degradation
- Handle network errors
- Manage context managers properly

```bash
python examples/error_handling.py
```

## Running Examples

All examples can be run directly:

```bash
# Run a specific example
python examples/basic_query.py

# Or with explicit credentials
INFINO_ACCESS_KEY="your_key" INFINO_SECRET_KEY="your_secret" python examples/basic_query.py
```

## Common Patterns

### Using Environment Variables

```python
import os
from infino_sdk import InfinoSDK

access_key = os.getenv("INFINO_ACCESS_KEY")
secret_key = os.getenv("INFINO_SECRET_KEY")
endpoint = os.getenv("INFINO_ENDPOINT", "https://api.infino.ws")

sdk = InfinoSDK(access_key, secret_key, endpoint)
# Your code here
```

### Error Handling

```python
from infino_sdk import InfinoError

try:
    result = sdk.some_operation()
except InfinoError as e:
    if e.status_code() == 404:
        print("Resource not found")
    else:
        print(f"Error: {e.message}")
```

### Session Management

```python
# Basic usage - SDK handles session automatically
sdk = InfinoSDK(access_key, secret_key, endpoint)
sdk.ping()

# The SDK manages HTTP sessions internally
# No need for manual session management
```

## Need Help?

- 📖 [Full Documentation](https://docs.infino.ai)
- 🐛 [Report Issues](https://github.com/infinohq/infino-sdk-python/issues)
- 📧 Email: support@infino.ai
