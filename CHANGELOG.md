# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-01-13

### Added
- Comprehensive SDK method documentation (`docs/sdk_methods.md`)
  - Detailed documentation for all SDK methods including parameters, return types, and examples
  - API response format specifications
- Enhanced examples with API response documentation
  - New `sdk_init.py` example for SDK initialization patterns
  - Expanded `file_upload.py` example with detailed response handling

### Fixed
- `get_dataset_schema()` method implementation
  - Corrected API endpoint from `/{dataset}/schema` to `/{dataset}/_schema`
  - Changed HTTP method from `HEAD` to `GET` for proper schema retrieval
- Dataset metadata response processing
  - Improved error handling and logging throughout SDK
  - Fixed exception chaining for better error traceability
  - Optimized logging format for better performance

### Changed
- Updated all examples with improved formatting and consistency
- Enhanced error messages and logging output

## [0.4.0] - 2025-12-17

### Added
- File upload API with support for JSON, JSONL, and CSV formats
  - `upload_file()` method with sync/async modes
  - `get_connector_job_status()` for polling upload job status
  - Automatic format detection from file extension
- OpenAPI 3.1 specification (`docs/openapi.yaml`)
- New Fino WebSocket chat example (`examples/fino_websocket_chat.py`)
- File upload example (`examples/file_upload.py`)
- Documentation for running Swagger UI locally

### Changed
- Restructured README with comprehensive API documentation
- Replaced `fino_nl.py` example with improved `fino_websocket_chat.py`
- Updated all examples for clarity and consistency
- Code formatting standardized with black

### Fixed
- CI/build configuration improvements

## [0.3.0] - 2025-11-23

### Added
- Initial public release of Infino Python SDK
- AWS SigV4 authentication for all HTTP requests and WebSocket connections
- Multiple query interfaces: SQL, QueryDSL (Elasticsearch/OpenSearch), PromQL, Natural Language (Fino AI)
- Dataset management: create, delete, query metadata/schema, list datasets
- Record operations: get, delete with query filtering
- Data ingestion: bulk JSON upload (NDJSON), metrics upload (Prometheus format), SQL upsert
- Fino AI conversation threads: create, manage, and query using natural language via WebSocket
- Data source connection management: connect to 50+ sources (Elasticsearch, OpenSearch, Snowflake, etc.)
- Import jobs: schedule and manage data imports from connected sources
- Governance & RBAC: user management, role management with field-level security
- Dataset enrichment policies
- Comprehensive error handling with typed exceptions (REQUEST, NETWORK, PARSE, RATE_LIMIT, TIMEOUT, INVALID_REQUEST)
- Configurable retry logic with exponential backoff
- Context manager support for resource cleanup
- Complete examples: basic queries, SQL analytics, Fino natural language, PromQL metrics, data upload, user management, error handling
