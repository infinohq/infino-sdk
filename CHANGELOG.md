# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
