# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Infino Python SDK** - Official Python SDK for Infino, a context engine that provides an intelligent unification layer for data stacks. The SDK enables querying 50+ data sources (Elasticsearch, OpenSearch, Snowflake, etc.) in natural language, SQL, QueryDSL, or PromQL through a single unified API.

**Core capabilities:**
- **Connect**: Access data sources without data movement
- **Query**: Multiple query interfaces (Natural Language via Fino AI, SQL, Query DSL, PromQL)
- **Correlate**: Cross-source data correlation via datasets
- **Govern**: Fine-grained RBAC for humans and agents

## Development Commands

### Setup
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install package in editable mode
pip install -e .
```

### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=infino_sdk --cov-report=html

# Run specific test file
pytest tests/test_query.py

# Run specific test
pytest tests/test_query.py::test_basic_query

# Run with verbose output
pytest -v
```

### Code Quality
```bash
# Format code
black infino_sdk tests

# Sort imports
isort infino_sdk tests

# Lint code
flake8 infino_sdk tests

# Type checking
mypy infino_sdk
```

### Build
```bash
# Build distribution
python -m build

# Check distribution
twine check dist/*
```

## Architecture

### Core Structure

The SDK is intentionally minimal with all implementation in a single file (`infino_sdk/lib.py`):

- **`infino_sdk/__init__.py`**: Public API exports (`InfinoSDK`, `InfinoError`)
- **`infino_sdk/lib.py`**: Complete SDK implementation (~1089 lines)
  - AWS SigV4 authentication for all HTTP requests
  - WebSocket support with SigV4 query parameter authentication
  - Request signing and retry logic
  - All API methods (datasets, queries, RBAC, connections, etc.)

### Authentication & Request Flow

**All API requests use AWS Signature Version 4 (SigV4):**

1. **Request Creation** → `request()` method
2. **Signature Generation** → `sign_request_headers()`
3. **Signing Key Derivation** → `derive_signing_key()` using date
4. **Canonical Request** → `create_canonical_request()` with sorted headers
5. **String to Sign** → `create_string_to_sign()` with algorithm, date, scope, canonical hash
6. **Signature Calculation** → HMAC-SHA256 chain: date → region → service → request
7. **Authorization Header** → Format: `AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...`
8. **Request Execution** → `execute_request()` with exponential backoff retries

**WebSocket Authentication** (`websocket_connect()`):
- Uses SigV4 authentication via query parameters (not headers)
- Generates signature for WebSocket upgrade request
- Appends authentication parameters to WebSocket URL

### API Method Categories

**Datasets** (for cross-source correlation):
- `create_dataset()`, `delete_dataset()`, `get_datasets()`
- `get_dataset_metadata()`, `get_dataset_schema()`
- `upload_json_to_dataset()`, `upsert_to_dataset()`, `upload_metrics_to_dataset()`
- `get_record()`, `delete_records()`, `enrich_dataset()`

**Query Methods** (multiple interfaces):
- `query_dataset_in_querydsl()` - Elasticsearch/OpenSearch Query DSL
- `query_dataset_in_sql()` - SQL queries
- `query_dataset_in_promql()`, `query_dataset_in_promql_range()` - PromQL for time-series
- `query_source()` - Query external connected sources directly

**Fino AI** (Natural Language):
- `websocket_connect()` - Async WebSocket connection for Fino conversations
- `list_threads()`, `create_thread()`, `get_thread()`, `update_thread()`, `delete_thread()`
- `add_thread_message()`, `clear_thread_messages()`, `send_message()`

**Connections** (external data sources):
- `get_sources()`, `get_connections()`, `create_connection()`
- `get_connection()`, `update_connection()`, `delete_connection()`
- `get_source_metadata()`, `create_import_job()`, `get_import_jobs()`, `delete_import_job()`

**RBAC** (governance):
- `create_user()`, `get_user()`, `update_user()`, `delete_user()`, `list_users()`
- `create_role()`, `get_role()`, `update_role()`, `delete_role()`, `list_roles()`
- `rotate_keys()` - API key rotation

**Utilities**:
- `ping()` - Health check
- `close()` - Close requests session
- Context manager support (`__enter__`, `__exit__`)

### Error Handling

The SDK uses a custom `InfinoError` exception with typed error categories:

```python
class InfinoError.Type(Enum):
    REQUEST = "request"      # HTTP request errors (4xx, 5xx)
    NETWORK = "network"      # Network/connection errors
    PARSE = "parse"          # JSON parsing errors
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    INVALID_REQUEST = "invalid_request"
```

**Error attributes:**
- `error_type`: Type of error from enum
- `message`: Error description
- `status_code()`: HTTP status code (if applicable)
- `url`: Request URL (if applicable)

**Retry logic:**
- 4xx errors: No retry (client errors)
- 5xx errors: Exponential backoff retry
- Network errors: Exponential backoff retry (except "Connection refused")
- Default: 3 max retries, 1s initial interval, 15s max interval

### Key Implementation Details

**AWS SigV4 Signing Constants:**
- Algorithm: `AWS4-HMAC-SHA256`
- Service: `es` (OpenSearch/Elasticsearch service)
- Region: `us-east-1`
- Signed headers: `host`, `x-amz-content-sha256`, `x-amz-date`, `content-type` (if present)

**Request Session:**
- Uses `requests.Session()` for connection pooling
- Default timeout: 180 seconds
- Session should be closed via `close()` or context manager

**Configuration:**
- `RetryConfig` class allows customizing retry behavior
- Pass custom `retry_config` to `InfinoSDK.__init__()`

## Code Style & Guidelines

### Style Rules (from CI)

- **Line length**: 127 characters (flake8 config)
- **Strings**: Use double quotes `"`
- **Formatting**: Use `black` for automatic formatting
- **Import sorting**: Use `isort`
- **Type hints**: Required for all public methods (Google-style docstrings)

### Testing Requirements

- **Framework**: pytest with pytest-asyncio for async tests
- **Coverage target**: >90% code coverage
- **Coverage config**: `.coveragerc` (excludes tests, venv, setup.py)
- **Test location**: `tests/` directory, naming convention `test_*.py`
- **Markers**: `@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.slow`, `@pytest.mark.asyncio`

### Commit Message Format

Follow conventional commits:
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### CI Pipeline

The `.github/workflows/ci.yml` runs:
1. **Lint**: black, isort, flake8, mypy
2. **Test**: pytest across Python 3.8-3.11 on ubuntu/macos/windows
3. **Security**: safety (dependency vulnerabilities), bandit (security linting)
4. **Build**: Python package distribution

## Important Notes

### When Adding New API Methods

1. Add method to `InfinoSDK` class in `lib.py`
2. Use `self.request()` for HTTP calls (handles signing automatically)
3. Follow existing patterns for method signatures and return types
4. Include comprehensive docstrings with Args, Returns, Raises, Example
5. Add tests in `tests/` directory
6. Update examples in `examples/` if user-facing

### Authentication Flow

Do not manually construct Authorization headers. Always use:
- `self.request()` for HTTP calls (auto-signs)
- `self.websocket_connect()` for WebSocket connections (auto-signs)

The signing logic is complex and error-prone if done manually.

### YAML Configuration Format

User and role configurations use YAML format with specific structure:

**User config:**
```yaml
Version: 2025-01-01
Password: SecurePassword123!
Roles:
  - role-name-1
  - role-name-2
```

**Role config:**
```yaml
Version: 2025-01-01
Permissions:
  - ResourceType: record
    Actions: [read, write]
    Resources: ["dataset-*"]
    Fields:
      Allow: ["field1", "field2"]
      Deny: ["sensitive_field"]
```

When creating user/role methods, pass YAML string as config (not dict).

### Bulk Operations

For bulk data upload (`upload_json_to_dataset`), use newline-delimited JSON format:
```
{"index": {"_id": "1"}}
{"field": "value"}
{"index": {"_id": "2"}}
{"field": "value2"}
```

The method overrides Content-Type header to `application/x-ndjson`.
