# Connectors

This document describes how the Infino Python SDK supports **connectors** (external data sources such as Elasticsearch, Snowflake, and BigQuery): what they are, which SDK methods to use, and how to find the required configuration for each connector.

## Overview

Connectors let you access external data sources **without moving data**. You create a connection (with credentials and settings), then you can:

- **Query** the source in place (e.g. QueryDSL for Elasticsearch, SQL for Snowflake)
- **Import** data from the source into Infino datasets on a schedule

**How it works:** Create a connection with `create_connection(source_type, config)` (e.g. Snowflake, BigQuery, Elasticsearch). Use the returned `connection_id` with `query_source(connection_id, dataset, query)` to run queries in the source’s native language, or with `create_import_job()` to schedule imports into Infino datasets. The [connector examples](../examples/connectors/) are runnable with the env vars described in this doc and in [examples/README.md](../examples/README.md).

The SDK talks to the Infino API, which manages connections and runs queries or imports.

## SDK surface

### Discovery

- **`get_sources()`** — Returns a list of available connector types. Each item typically includes `id`, `name`, `description`, `category`, and `auth_strategy`. Use this to see which connectors your Infino deployment supports.

### Connection lifecycle

- **`create_connection(source_type, config)`** — Create a connection. `source_type` is the connector id (e.g. `"elasticsearch"`, `"snowflake"`). `config` is a dict with a `"config"` key containing the connection configuration. The `"name"` field must be inside the `"config"` object. Example:
  ```python
  config = {
      "config": {
          "name": "My Connection",
          "account": "...",
          "pat_token": "...",
          # ... other connector-specific fields
      }
  }
  sdk.create_connection("snowflake", config)
  ```
- **`get_connections()`** — List active connections.
- **`get_connection(connection_id)`** — Get status and details of a connection.
- **`update_connection(connection_id, config)`** — Update a connection's configuration.
- **`delete_connection(connection_id)`** — Remove a connection.

### Querying a connected source

- **`query_source(connection_id, dataset, query)`** — Run a query in the source's native language. For Elasticsearch/OpenSearch the `query` is a QueryDSL JSON string and `dataset` is the **index name**. For Snowflake/BigQuery the `query` is a SQL string and `dataset` is the **database name** (query scope); table names go in the SQL (e.g. `SELECT * FROM my_table`). The SDK wraps the query in `{"query": "..."}` and adds the `x-infino-connection-id` header. Uses POST.
- **`get_source_metadata(connection_id, dataset)`** — Get metadata (schema, mappings, etc.) for the given scope. Use the same `dataset` as for queries: index name for ES/OpenSearch, database name for Snowflake/BigQuery.

### Import jobs

- **`create_import_job(source_type, config)`** — Create an import job from a data source into an Infino dataset. Config typically includes `source_id`, `target_dataset`, `query`, and optionally `schedule` (cron).
- **`get_import_jobs()`** — List import jobs.
- **`delete_import_job(job_id)`** — Delete an import job.

### File upload (file connector)

- **`upload_file(dataset, file_path, format, ...)`** — Upload a file (JSON, JSONL, CSV) to a dataset. This uses the built-in file connector; no separate "connection" is created.
- **`get_connector_job_status(run_id)`** — Poll status of an async upload or other connector job.

See the main [README](../README.md) and [SDK methods](sdk_methods.md) for detailed method signatures and examples.

## Request and Response Formats

This section documents the request and response structures for connector operations.

### `get_source_metadata()` Request and Response

**Request Format:**

- **HTTP Method:** GET
- **Headers:** `x-infino-connection-id: <connection_id>`
- **Endpoint:** `/source/{connection_id}/{dataset}/metadata`

**Response Format:**

The response structure varies by source type. Common fields include:

- **SQL Sources:** May include `columns`, `schema`, `tables`, etc.
- **Elasticsearch/OpenSearch:** May include `mappings`, `settings`, `aliases`, etc.

**Example (SQL Source):**

```json
{
  "columns": [
    {
      "name": "column_name",
      "type": "VARCHAR",
      "nullable": true
    }
  ],
  "schema": "public",
  "table": "table_name"
}
```

**Example (Elasticsearch):**

```json
{
  "mappings": {
    "properties": {
      "field1": {"type": "text"},
      "field2": {"type": "keyword"}
    }
  },
  "settings": {...}
}
```

**Note:** Always check response keys dynamically as the structure varies by connector type.

### `create_connection()` Request and Response

**Request Format:**

```json
{
  "config": {
    "name": "My Connection",
    "account": "account.snowflakecomputing.com",
    "pat_token": "...",
    "warehouse": "COMPUTE_WH",
    "database": "PRODUCTION_DB"
  }
}
```

- **HTTP Method:** POST
- **Endpoint:** `/source/{source_type}` (e.g., `/source/snowflake`)

**Response Format:**

```json
{
  "connection_id": "conn-abc123def456",
  "message": "Connection created successfully",
  "created_at": "2026-01-15T10:30:00.000000000+00:00",
  "auth": null
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `connection_id` | string | Unique identifier for the created connection |
| `message` | string | Success message |
| `created_at` | string | ISO 8601 timestamp of creation |
| `auth` | object\|null | Authentication details (null for native connections) |

### `get_connection()` Response

```json
{
  "id": "conn-abc123def456",
  "type": "snowflake",
  "status": "connected",
  "created_at": "2026-01-15T10:30:00.000000000+00:00",
  "updated_at": "2026-01-15T10:30:00.000000000+00:00",
  "config": {...},
  "query_type": "sql"
}
```

## Where connector configs are defined

The **authoritative** connector definitions (connection types, required/optional fields, labels, descriptions) live in the Infino connector service, not in the SDK.

- **Path (in the Infino repo):** `infino/services/connector/src/services/schemas/<connector_id>.rs`
- Each connector has one Rust file. The file exports a static JSON value (e.g. `ELASTICSEARCH_SCHEMA`) built with `json!({...})`. That JSON has:
  - **`id`** — Connector id (e.g. `"elasticsearch"`, `"snowflake"`).
  - **`name`**, **`description`**, **`category`**, **`disabled`**, **`supported_modes`**.
  - **`connections`** — Array of connection/auth types. Each entry has **`type`** (e.g. `basic_auth`, `pat`), **`label`**, **`integration_type`** (`"native"` or `"third_party:nango"`), and **`fields`**.
  - **`fields`** (inside each connection) — Array of config fields. Each field has **`name`** (the config key), **`label`**, **`description`**, **`required`** (boolean), **`type`**/ **`subtype`**, **`placeholder`**, **`default`**, etc.
  - Optional: **`configuration`**, **`advanced_configuration`** for extraction/data options.

The SDK's `get_sources()` returns lightweight metadata (id, name, description, category, auth_strategy). For the **full list of fields and which are required**, use the schema files in the connector service.

## How to determine required configs

1. Open the schema file for the connector in the Infino repo:  
   `infino/services/connector/src/services/schemas/<connector_id>.rs`
2. In the static `json!({...})`, find the **`connections`** array and choose the connection type you want (e.g. `basic_auth`, `api_key`, `pat`, `user_password`).
3. In that connection's **`fields`** array, every object with **`"required": true`** is a required config key; the key name is the field's **`name`**. All other fields in `fields` are optional (unless otherwise documented).

This process is the single source of truth when you need to know what to pass in `config` for `create_connection(source_type, config)` or for import job config.

## Reference: common connectors

The following is a short reference derived from the connector service schemas. For the exact, up-to-date list of fields and requirements, always refer to the schema file in the Infino repo.

| Connector | Id | Connection types | Required config (example for one type) | Optional (example) |
|-----------|----|------------------|----------------------------------------|---------------------|
| **Elasticsearch** | `elasticsearch` | `basic_auth`, `api_key`, `bearer_token`, `none` | **basic_auth:** `base_url`, `username`, `password` | `timeout_secs`, `accept_invalid_certs` |
| | | | **api_key:** `base_url`, `api_key` | `timeout_secs`, `accept_invalid_certs` |
| | | | **none:** `base_url` | `timeout_secs`, `accept_invalid_certs` |
| **OpenSearch** | `opensearch` | Same shape as Elasticsearch (see `opensearch.rs`) | Same as Elasticsearch for the chosen auth type | Same as Elasticsearch |
| **Snowflake** | `snowflake` | `pat`, `user_password` | **pat:** `account`, `pat_token`, `warehouse`, `database` | `schema`, `role` |
| | | | **user_password:** `account`, `user`, `password`, `warehouse`, `database` | `schema`, `role` |
| **BigQuery** | `bigquery` | `service_account_key` | **service_account_key:** `dataset_ids` (comma-separated), `service_account_key` (JSON) | `project_id` (auto-extracted from service account key) |
| **File** | `file` | N/A (no connection object) | Use `upload_file(dataset, file_path, format, ...)`. See [File upload](../README.md#file-upload) in the README. | `batch_size`, `async_mode` |

- **Important**: When calling `create_connection(source_type, config)`, wrap all fields (including `name`) inside a `"config"` key:
  ```python
  config = {
      "config": {
          "name": "Connection Name",
          # ... connector-specific fields
      }
  }
  ```
- For **Elasticsearch** and **OpenSearch**, fields like `host`, `username`, `password` go directly in the `config` object.
- **Snowflake** supports both PAT (`pat_token`) and username/password (`user`, `password`) authentication. Use `pat_token` for Programmatic Access Token authentication (recommended).
- **BigQuery** requires a service account key JSON (`service_account_key`) and comma-separated dataset IDs (`dataset_ids`). The service account must have BigQuery Data Viewer and BigQuery Job User roles.

## Examples

- [examples/connectors/basic_connections.py](../examples/connectors/basic_connections.py) — Create, list, get, update, delete connections.
- [examples/connectors/query_elasticsearch.py](../examples/connectors/query_elasticsearch.py) — Query Elasticsearch with QueryDSL and get metadata.
- [examples/connectors/query_sql_sources.py](../examples/connectors/query_sql_sources.py) — Query Snowflake/BigQuery with SQL.
- [examples/connectors/import_jobs.py](../examples/connectors/import_jobs.py) — Create, list, and delete import jobs.

### Running the connector examples

All connector examples need Infino credentials:

```bash
export INFINO_ACCESS_KEY="your_access_key"
export INFINO_SECRET_KEY="your_secret_key"
export INFINO_ENDPOINT="https://api.infino.ws"
```

- **basic_connections.py** — Optional: set `SNOWFLAKE_*`, `BIGQUERY_*`, or `ELASTICSEARCH_*` env vars to create real connections; otherwise it discovers sources and lists existing connections.
- **query_sql_sources.py** — Requires a SQL connection id and database name: `SQL_CONNECTION_ID`, `SQL_DATASET` (or `SNOWFLAKE_DATABASE`). Optional: `SQL_TABLE_NAME` for the example table used in the SQL (default `sales_data`). For Snowflake, `SQL_DATASET` is the **database name**, not the table name.
- **query_elasticsearch.py** — Requires `ES_CONNECTION_ID` and `ES_INDEX` (the index name).
- **import_jobs.py** — Requires a connection id and job config; see the script for env vars.

See [examples/README.md](../examples/README.md) for full run instructions.
