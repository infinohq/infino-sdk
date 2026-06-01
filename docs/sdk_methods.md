# Infino SDK API Documentation

## Configuration Functions

### ping
**Description:** Health check endpoint to verify API connectivity and get version information.

**Input Parameters:** None

**Output:**
```json
{
  "version": "2025-06-30"
}
```

---

### close
**Description:** Close the underlying HTTP session. Should be called when SDK instance is no longer needed.

**Input Parameters:** None

**Output:** None (cleanup only)

---

## Dataset Functions

### create_dataset
**Description:** Create an empty dataset. Returns success even if dataset already exists.

**Input Parameters:**
- `dataset` (str, required): The name of the dataset to create

**Output:**
```json
{
  "acknowledged": true,
  "index": "test_auto_dataset_lifecycle"
}
```

---

### delete_dataset
**Description:** Delete a dataset and all its records.

**Input Parameters:**
- `dataset` (str, required): The name of the dataset to delete

**Output:**
```json
{
  "acknowledged": true
}
```

---

### get_datasets
**Description:** Query Infino for metadata on all current datasets.

**Input Parameters:** None

**Output:**
```json
[
  {
    "health": "green",
    "status": "open",
    "index": "my-logs",
    "uuid": "my-logs-uuid",
    "pri": "1",
    "rep": "0",
    "docs.count": "0",
    "docs.deleted": "0",
    "store.size": "2.8kb",
    "pri.store.size": "2.8kb"
  }
]
```

---

### get_dataset_metadata
**Description:** Query a dataset for its metadata (status, health, document count, etc.).

**Input Parameters:**
- `dataset` (str, required): The name of the dataset

**Output:**
```json
{
  "health": "green",
  "status": "open",
  "index": "test_auto_dataset_lifecycle",
  "uuid": "test_auto_dataset_lifecycle-uuid",
  "pri": "1",
  "rep": "0",
  "docs.count": "0",
  "docs.deleted": "0",
  "store.size": "0.0b",
  "pri.store.size": "0.0b"
}
```

---

### get_dataset_schema
**Description:** Query a dataset for its schema (field mappings and types).

**Input Parameters:**
- `dataset` (str, required): The name of the dataset

**Output:**
```json
{
  "@timestamp": {
    "source": "Logs",
    "infino_type": "ISO8601Date"
  },
  "name": {
    "source": "Logs",
    "infino_type": "String"
  },
  "price": {
    "source": "Logs",
    "infino_type": "Float"
  }
}
```

Each field contains:
- `source`: The data source type
- `infino_type`: The Infino data type (e.g., "ISO8601Date", "String", "Float", "Integer")

---

### upload_json_to_dataset
**Description:** Upload records to a dataset in NDJSON (newline-delimited JSON) format using Elasticsearch bulk API format.

**Input Parameters:**
- `dataset` (str, required): The name of the target dataset
- `payload` (str, required): Newline-delimited JSON with alternating action and document lines

**Output:**
```json
{
  "took": 30,
  "errors": false,
  "items": [
    {"index": {"_id": "1", "result": "created"}},
    {"index": {"_id": "2", "result": "created"}}
  ]
}
```

---

### upsert_to_dataset
**Description:** Execute SQL INSERT or UPDATE statements against a dataset.

**Input Parameters:**
- `query` (str, required): The SQL INSERT or UPDATE statement

**Output:**
```json
{
  "has_joins": false,
  "execution_time": 0,
  "statement_type": "Insert",
  "affected_rows": 1,
  "columns": [],
  "rows": [],
  "aggregations": null,
  "error_message": null,
  "query_events": null,
  "order_by": [],
  "limit": null,
  "distinct": false,
  "group_by_columns": [],
  "table_names": []
}
```

---

### upload_metrics_to_dataset
**Description:** Upload Prometheus-format metrics to a dataset.

**Input Parameters:**
- `dataset` (str, required): The name of the target dataset
- `payload` (str, required): Metrics in Prometheus text exposition format

**Output:**
```json
["Successfully added exposition metrics."]
```

---

### get_record
**Description:** Retrieve a single record from a dataset by its ID.

**Input Parameters:**
- `dataset` (str, required): The name of the dataset
- `record_id` (str, required): The unique identifier of the record

**Output:**
```json
{
  "_index": "my-dataset",
  "_id": "1",
  "_version": 1,
  "_seq_no": 0,
  "_primary_term": 1,
  "found": true,
  "_source": {
    "name": "Product 1",
    "price": 29.99
  }
}
```

---

### delete_records
**Description:** Delete records from a dataset matching the provided QueryDSL query.

**Input Parameters:**
- `dataset` (str, required): The name of the dataset
- `query` (str, required): A JSON query string defining which records to delete (QueryDSL format)

**Output:**
```json
0
```
(Returns integer count of deleted records)

---

### enrich_dataset
**Description:** Update enrichment policy for a dataset to configure field matching and enrichment rules.

**Input Parameters:**
- `dataset` (str, required): The name of the dataset
- `policy` (str, required): A JSON string defining the enrichment policy

**Output:** Enrichment policy update confirmation

---

## Query Functions

### query_dataset_in_querydsl
**Description:** Query a dataset using Elasticsearch/OpenSearch Query DSL syntax. Supports full-text search, term queries, aggregations, and more.

**Input Parameters:**
- `dataset` (str, required): The name of the dataset to query
- `query` (str, required): The JSON query string in Query DSL format

**Output:**
```json
{
  "took": 5,
  "timed_out": false,
  "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
  "hits": {
    "total": {"value": 100, "relation": "eq"},
    "max_score": 1.0,
    "hits": [
      {
        "_index": "my-dataset",
        "_id": "1",
        "_score": 1.0,
        "_source": {"name": "Product 1"}
      }
    ]
  }
}
```

---

### query_dataset_in_sql
**Description:** Query one or more datasets using SQL syntax. Supports SELECT, JOIN, aggregations, and cross-dataset queries.

**Input Parameters:**
- `query` (str, required): The SQL query string

**Output:**
```json
{
  "has_joins": false,
  "execution_time": 2,
  "statement_type": "Select",
  "affected_rows": 2,
  "columns": [
    {
      "alias": null,
      "name": {"Column": {"name": "product", "table_identifier": null}},
      "data_type": "String"
    }
  ],
  "rows": [
    {
      "values": {
        "product": {"String": "laptop"},
        "price": {"Integer": 1200}
      }
    }
  ],
  "aggregations": null,
  "error_message": null,
  "query_events": null,
  "order_by": [],
  "limit": null,
  "distinct": false,
  "group_by_columns": [],
  "table_names": []
}
```

---

### query_dataset_in_promql
**Description:** Query time-series data using PromQL (Prometheus Query Language). Returns instant vector results.

**Input Parameters:**
- `query` (str, required): The PromQL query expression
- `dataset` (str, optional): Optional dataset name to restrict the query scope

**Output:**
```json
{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": [
      {
        "metric": {"__name__": "up", "job": "prometheus"},
        "value": [1609459200, "1"]
      }
    ]
  }
}
```

---

### query_dataset_in_promql_range
**Description:** Query time-series data using PromQL with a time range. Returns matrix results.

**Input Parameters:**
- `query` (str, required): The PromQL query expression
- `start` (int, required): Start timestamp in Unix seconds
- `end` (int, required): End timestamp in Unix seconds
- `step` (int, required): Query resolution step width in seconds
- `dataset` (str, optional): Optional dataset name to restrict the query scope

**Output:**
```json
{
  "status": "success",
  "data": {
    "resultType": "matrix",
    "result": [
      {
        "metric": {"__name__": "up", "job": "prometheus"},
        "values": [
          [1609459200, "1"],
          [1609459260, "1"]
        ]
      }
    ]
  }
}
```

---

### query_source
**Description:** Query a data source connection using its native DSL.

**Input Parameters:**
- `connection_id` (str, required): The ID of the connection to query
- `dataset` (str, required): The target dataset/table/index within the source
- `query` (str, required): The query string in the source's native language

**Output:** Query results in source-native format (structure varies by source type)

---

## Fino AI Functions

### websocket_connect
**Description:** Connect to WebSocket endpoint with AWS SigV4 authentication for streaming responses.

**Input Parameters:**
- `path` (str, required): The WebSocket path to connect to
- `headers` (dict, optional): Optional additional headers

**Output:** WebSocket connection object

> **Note:** When using streaming mode (`streaming: true` in thread config), see [Streaming Responses Documentation](./streaming_responses.md) for the complete response format and message types.

---

### list_threads
**Description:** List all Fino threads.

**Input Parameters:** None

**Output:**
```json
[]
```
(Returns array of thread objects, may be empty)

---

### create_thread
**Description:** Create a new Fino thread.

**Input Parameters:**
- `config` (dict, required): Configuration dictionary for the thread. Contains the following items
  - `name`: Name of the thread
  - `sources` (optional): Starts the thread in restricted mode, limiting Fino to only the specified indices. When omitted, Fino uses **auto mode** to automatically determine the best index to query. `sources` is a list where each item has:
    - `index_name`: Name of the index
    - `connection_id`: id of the index source. Usually `infino`, but can be different in case of connectors
  - `streaming`: whether to start the thread in streaming mode. When `true`, responses are delivered progressively via WebSocket. See [Streaming Responses Documentation](./streaming_responses.md) for the complete response format.

**Sample Input:**
```json
{"name":"Detailed Dashboard","sources": [{"index_name": "sample_flights", "connection_id": "infino" }],"streaming":true}
```

**Output:**
```json
{
  "id": "00000000-0000-0000-0000-000000000001",
  "user_id": "user_1",
  "name": "test_auto_minimal_thread",
  "status": "ongoing", // one of "ongoing" or "completed"
  "workflow_name": "fino-alpha-1",
  "created_at": "2025-12-16T12:18:07.714853+00:00",
  "updated_at": "2025-12-16T12:18:07.714853+00:00",
  "messages": [],
  "viz_context": {},
  "sources": [],
  "historical_context": null,
  "is_owner": true,
  "user_permission": "OWNER",
  "shared_with_users": []
}
```

---

### get_thread
**Description:** Retrieve a specific Fino thread.

**Input Parameters:**
- `thread_id` (str, required): The ID of the thread to retrieve

**Output:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-01-15T11:00:00Z",
  "metadata": {"name": "My Thread"},
  "messages": [
    {"role": "user", "content": "Hello", "metadata": {}}
  ]
}
```

---

### update_thread
**Description:** Update a Fino thread metadata.

**Input Parameters:**
- `thread_id` (str, required): The ID of the thread to update
- `config` (dict, required): The new configuration/metadata for the thread

**Output:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-01-15T12:00:00Z",
  "metadata": {"name": "Updated Thread Name"},
  "messages": []
}
```

---

### delete_thread
**Description:** Delete a Fino thread.

**Input Parameters:**
- `thread_id` (str, required): The ID of the thread to delete

**Output:**
```json
true
```

---

### add_thread_message
**Description:** Add a message to a specific Fino thread.

**Input Parameters:**
- `thread_id` (str, required): The ID of the thread
- `message` (dict, required): The message object to add. Should contain the following
  - `role`: role of the message creator. One of "user", "assistant", "system"
  - `content`: object containing the contents of the message. Contains 
    - `user_message`: user query that fino answers
  ** Sample message **
  ```json
  {
    "role": "user",
    "content": {
      "user_message": "What is the sales trend for Q4"
    }
  }
  ```

**Output:**
```json
"00000000-0000-0000-0000-000000000002"
```
(Returns message UUID as string)

---

### clear_thread_messages
**Description:** Remove all messages from a Fino thread.

**Input Parameters:**
- `thread_id` (str, required): The ID of the thread to clear

**Output:**
```json
true
```

---

### send_message
**Description:** Send a message to Fino using the simplified API for natural language queries.

**Input Parameters:**
- `payload` (dict, required): The message payload containing message and optional context

**Output:**
```json
"00000000-0000-0000-0000-000000000003"
```
(Returns message UUID as string)

---

## Connections Functions

### get_sources
**Description:** Get a list of available data source types.

**Input Parameters:** None

**Output:**
```json
{
  "id": "datadog",
  "name": "Datadog",
  "category": "Observability",
  "description": "Connect to logs, metrics, and traces from Datadog APIs",
  "capabilities": ["batch"],
  "disabled": true,
  "query_type": "none",
  "auth_strategy": "nango"
}
```

---

### get_connections
**Description:** Get a list of active data source connections.

**Input Parameters:** None

**Output:**
```json
[
  {
    "id": "conn-123",
    "type": "elasticsearch",
    "status": "connected",
    "created_at": "2025-01-15T10:30:00Z",
    "config": {"host": "localhost", "port": 9200}
  }
]
```

---

### create_connection
**Description:** Create a new data source connection.

**Input Parameters:**
- `source_type` (str, required): Type of data source
- `config` (dict, required): Connection configuration

**Output:**
```json
{
  "id": "conn-456",
  "type": "elasticsearch",
  "status": "connected",
  "created_at": "2025-01-15T11:00:00Z",
  "config": {"host": "localhost", "port": 9200}
}
```

---

### get_connection
**Description:** Get status of a data source connection.

**Input Parameters:**
- `connection_id` (str, required): The ID of the connection

**Output:**
```json
{
  "id": "conn-123",
  "type": "elasticsearch",
  "status": "connected",
  "created_at": "2025-01-15T10:30:00Z",
  "config": {"host": "localhost", "port": 9200}
}
```

---

### update_connection
**Description:** Update a data source connection.

**Input Parameters:**
- `connection_id` (str, required): The ID of the connection to update
- `config` (dict, required): The new configuration parameters

**Output:**
```json
{
  "id": "conn-123",
  "type": "elasticsearch",
  "status": "connected",
  "created_at": "2025-01-15T10:30:00Z",
  "config": {"host": "updated-host", "port": 9300}
}
```

---

### delete_connection
**Description:** Remove a data source connection.

**Input Parameters:**
- `connection_id` (str, required): The ID of the connection to delete

**Output:**
```json
{
  "acknowledged": true
}
```

---

### get_source_metadata
**Description:** Get metadata from a data source connection.

**Input Parameters:**
- `connection_id` (str, required): The ID of the connection
- `dataset` (str, required): The dataset/table name in the source

**Output:** Source metadata and field mappings (structure varies by source type)

---

### create_import_job
**Description:** Create an import job from a data source to a dataset.

**Input Parameters:**
- `source_type` (str, required): Type of data source
- `config` (dict, required): Job configuration including source connection, query, and schedule

**Output:**
```json
{
  "job_id": "job-789",
  "source_id": "conn-123",
  "target_dataset": "my_dataset",
  "status": "pending",
  "schedule": "0 * * * *",
  "created_at": "2025-01-15T12:00:00Z",
  "last_run": null
}
```

---

### get_import_jobs
**Description:** Get list of all import jobs.

**Input Parameters:** None

**Output:**
```json
[
  {
    "job_id": "job-789",
    "source_id": "conn-123",
    "target_dataset": "my_dataset",
    "status": "pending",
    "schedule": "0 * * * *",
    "created_at": "2025-01-15T12:00:00Z",
    "last_run": null
  }
]
```

**Job Status Values:** `pending`, `running`, `completed`, `failed`

---

### delete_import_job
**Description:** Delete an import job.

**Input Parameters:**
- `job_id` (str, required): The ID of the job to delete

**Output:**
```json
{
  "acknowledged": true
}
```

---

## RBAC & Governance Functions

### create_user
**Description:** Create a user in your account. Accepts YAML or JSON configuration.

**Input Parameters:**
- `name` (str, required): The username for the new user
- `config` (dict, required): User configuration (password, roles)

**Output:**
```json
{
  "account_id": "2025******",
  "access_key": "IAK_XXXXXXXXXXXXXXXX",
  "secret_key": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "username": "test_auto_test_user",
  "password": "TestP@ssw0rd123!"
}
```

---

### get_user
**Description:** Get details for a user in your account.

**Input Parameters:**
- `name` (str, required): The username

**Output:**
```json
{
  "test_auto_test_user": {
    "Version": "2025-01-01",
    "Roles": ["test_auto_test_role"],
    "account_id": "2025******"
  }
}
```

---

### update_user
**Description:** Update a user in your account.

**Input Parameters:**
- `name` (str, required): The username to update
- `config` (dict, required): The new configuration (password, roles)

**Output:**
```json
{
  "name": "testuser",
  "roles": ["admin", "analyst"],
  "created_at": "2025-01-15T10:30:00Z"
}
```

---

### delete_user
**Description:** Delete a user from your account.

**Input Parameters:**
- `name` (str, required): The username to delete

**Output:**
```json
{
  "acknowledged": true
}
```

---

### list_users
**Description:** List all users in your account.

**Input Parameters:** None

**Output:**
```json
{
  "user1": {
    "Version": "2025-01-01",
    "Roles": ["admin-role"],
    "account_id": "2025******"
  },
  "admin": {
    "Version": "2025-01-01",
    "Roles": ["admin-role"],
    "account_id": "2025******"
  }
}
```

---

### create_role
**Description:** Create a role in your account. Accepts YAML or JSON configuration.

**Input Parameters:**
- `name` (str, required): The name of the role
- `config` (dict, required): Role configuration (permissions)

**Output:**
```json
{
  "acknowledged": true
}
```

---

### get_role
**Description:** Get details for a role in your account including permissions.

**Input Parameters:**
- `name` (str, required): The role name

**Output:**
```json
{
  "test_auto_test_role": {
    "Version": "2025-01-01",
    "Permissions": [
      {
        "Effect": "Allow",
        "ResourceType": "record",
        "Actions": ["read"],
        "Resources": ["logs-*", "metrics-*"],
        "Fields": {}
      }
    ]
  }
}
```

---

### update_role
**Description:** Update a role in your account.

**Input Parameters:**
- `name` (str, required): The role name to update
- `config` (dict, required): The new configuration (permissions)

**Output:**
```json
{
  "name": "analyst",
  "permissions": [
    {
      "resource_type": "dataset",
      "actions": ["read"],
      "resources": ["*"]
    }
  ],
  "created_at": "2025-01-15T10:30:00Z"
}
```

---

### delete_role
**Description:** Delete a role from your account.

**Input Parameters:**
- `name` (str, required): The role name to delete

**Output:**
```json
{
  "acknowledged": true
}
```

---

### list_roles
**Description:** List all roles in your account.

**Input Parameters:** None

**Output:**
```json
{
  "infino_admin_role": {
    "Version": "2025-01-01",
    "Permissions": [
      {
        "Effect": "Allow",
        "ResourceType": "record",
        "Actions": ["read", "write"],
        "Resources": ["infino_accounts*"],
        "Fields": {}
      }
    ]
  },
  "kibana_user": {
    "Version": "2025-01-01"
  }
}
```

---

### rotate_keys
**Description:** Rotate API keys for a user. Returns new access key and secret key.

**Input Parameters:**
- `username` (str, required): The username whose keys should be rotated

**Output:**
```json
{
  "access_key": "AKIAIOSFODNN7EXAMPLE",
  "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
```

---

## Visualization Functions

A **visualization** is a saved chart definition: where to get the data (a SQL query) and how to render it (chart type, mapping, formatting). Each visualization is identified by an id you can fetch, update, or execute on demand.

See [dashboards.md](./dashboards.md) for the full feature guide — quickstart, layout sizing, troubleshooting, and an end-to-end runnable example. The reference below documents the input parameters and response shape of each SDK method.

The API wraps each saved object in a small response shape: `id`, `created_at`, `updated_at`, and `kind` sit alongside the saved object, which lives in `attributes`. The same shape is returned by `create_*`, `get_*`, and `update_*` (shown in full under [create_visualization](#create_visualization)).

### create_visualization
**Description:** Create a SQL-backed visualization. The server fills mapping / options / tags / limit / etc. — minimum body is `title`, `source` (with `kind`, `index`, and `sql.raw_query`), and `chart.type`.

**Input Parameters:**
- `spec` (dict, required): Visualization specification. Minimum:
  - `title` (str): Display title
  - `source.kind` (str): Currently only `"sql"`
  - `source.index` (str): Dataset name (e.g. `"license_events"`)
  - `source.sql.raw_query` (str): Non-empty SQL string
  - `chart.type` (str): One of `bar`, `horizontalBar`, `line`, `area`, `pie`, `heatmap`, `scatter`, `metric`, `gauge`

**Sample Input:**
```json
{
  "title": "Top denied features",
  "source": {
    "kind": "sql",
    "index": "license_events",
    "sql": {
      "raw_query": "SELECT feature, COUNT(*) AS denials FROM license_events WHERE event_type = 'DENIED' GROUP BY feature ORDER BY denials DESC LIMIT 10"
    }
  },
  "chart": {"type": "bar"}
}
```

**Output:**
```json
{
  "id": "0a9c8f...",
  "kind": "visualization",
  "created_at": "2026-05-15T10:30:00Z",
  "updated_at": "2026-05-15T10:30:00Z",
  "attributes": {
    "id": "0a9c8f...",
    "schema_version": "v1",
    "title": "Top denied features",
    "source": {"kind": "sql", "index": "license_events", "sql": {"raw_query": "..."}},
    "chart": {"type": "bar"},
    "mapping": {"x": null, "y": [], "series": null},
    "options": {"metric_formatting": null},
    "tags": [],
    "created_at": "2026-05-15T10:30:00Z",
    "updated_at": "2026-05-15T10:30:00Z",
    "created_by": "alice"
  }
}
```

---

### get_visualization
**Description:** Fetch a saved visualization by id.

**Input Parameters:**
- `viz_id` (str, required): The visualization id

**Output:** Same response shape as `create_visualization`.

---

### list_visualizations
**Description:** List visualizations the caller can see, with pagination.

**Input Parameters:**
- `limit` (int, optional): Page size (server default 500, max 1000)
- `offset` (int, optional): Page offset (default 0)

**Output:**
```json
{
  "items": [
    {"id": "0a9c8f...", "kind": "visualization", "attributes": {"...": "..."}},
    {"id": "1b8d7e...", "kind": "visualization", "attributes": {"...": "..."}}
  ]
}
```

---

### update_visualization
**Description:** Patch a visualization with a partial spec. Send only the fields you want to change — anything you don't send is preserved. Send a field as `null` to unset it. Lists are replaced wholesale, not merged element-wise (to add to a list, resend the full updated list). `id`, `schema_version`, `created_at`, and `created_by` are immutable; the server ignores attempts to overwrite them. *(Wire format: RFC 7396 JSON Merge Patch.)*

**Input Parameters:**
- `viz_id` (str, required): The visualization id
- `partial` (dict, required): Subset of the visualization spec to merge in

**Sample Input:**
```json
{
  "title": "Top denied features (Q3)",
  "source": {"sql": {"limit": 200}}
}
```

**Output:** The updated visualization (same response shape as `create_visualization`).

---

### delete_visualization
**Description:** Delete a visualization by id.

**Input Parameters:**
- `viz_id` (str, required): The visualization id

**Output:**
```json
{"acknowledged": true}
```

---

### execute_visualization
**Description:** Run the saved SQL and return plot-ready rows. Currently supports SQL visualizations (`source.kind == "sql"`) with `source.sql.raw_query`. Runtime filter / time-range overrides are not yet wired through — bake them into the SQL string for now.

**Input Parameters:**
- `viz_id` (str, required): The visualization id

**Output:**
```json
{
  "columns": [
    {"name": "Feature", "type": "string"},
    {"name": "Denials", "type": "number"}
  ],
  "rows": [
    {"Feature": "synopsys_vcs", "Denials": 1284},
    {"Feature": "cadence_innovus", "Denials": 902}
  ],
  "metadata": {
    "source_kind": "sql",
    "row_count": 2,
    "truncated": false,
    "took_ms": 47,
    "executed_query": "SELECT `feature_name` AS `Feature`, ..."
  }
}
```

Column `type` is normalised to `string` / `number` / `boolean` / `date` / `null`.

---

### to_echarts_option
**Description:** Pure function (no network call) that turns a saved visualization plus its executed rows into a render-ready shape. Pass in the result of `get_visualization(viz_id)` (or just its `attributes`) and the result of `execute_visualization(viz_id)`.

**Input Parameters:**
- `viz` (dict, required): The visualization response or its `attributes` block
- `data` (dict, required): The output of `execute_visualization(viz_id)`

**Output:** A dict whose `kind` tells you which branch to render:

- `"echarts"` — `result["option"]` is plain ECharts JSON you can pass straight to `echarts.setOption(...)` in the browser, or to pyecharts in Python. Covers `bar`, `horizontalBar`, `line`, `area`, `pie`, `heatmap`, `scatter`.
- `"table"` — `result["columns"]` and `result["rows"]` for inline HTML / pandas rendering. Returned when `chart.type == "table"` or when the data doesn't fit the declared chart type.
- `"metric"` — `result["value"]` is the single aggregated number with optional `result["formatting"]` (`prefix`, `suffix`, `decimals`, `abbreviate`, `thousands_separator`). Returned when `chart.type == "metric" | "gauge"`.

---

## Dashboard Functions

A **dashboard** is an ordered list of panels. Each panel either references a saved visualization (`viz_id`) or carries inline content (markdown / divider). Layout is a 48-column CSS grid with per-panel `{x, y, w, h}` placement — see [dashboards.md](./dashboards.md#layout) for sizing.

The same response shape (`id`, `created_at`, `updated_at`, `kind`, plus the dashboard itself in `attributes`) is used by all dashboard endpoints.

### create_dashboard
**Description:** Create a dashboard. Minimum body is `{"title"}`. `panels` defaults to `[]`. Each panel needs `viz_id` for visualization panels, `content` for markdown panels, or nothing for dividers; `kind` defaults to `"visualization"`. Omit `layout` on every panel and the server auto-flows them into a 2-column grid.

**Input Parameters:**
- `spec` (dict, required):
  - `title` (str, required): Display title
  - `panels` (list, optional): Ordered panel list

**Sample Input:**
```json
{
  "title": "FlexLM License Overview",
  "panels": [
    {"viz_id": "0a9c8f...", "layout": {"x": 0,  "y": 0,  "w": 12, "h": 8}},
    {"viz_id": "1b8d7e...", "layout": {"x": 12, "y": 0,  "w": 18, "h": 16}}
  ]
}
```

**Panel fields:**

| Field | Type | Notes |
|-------|------|-------|
| `kind` | `"visualization"` \| `"markdown"` \| `"divider"` | Defaults to `"visualization"` |
| `viz_id` | string | Required for visualization panels |
| `content` | string | Required for markdown panels |
| `layout` | `{x, y, w, h}` | 48-column grid; 1 row unit ≈ 22px in the reference renderer |
| `title_override` | string \| null | Display title; falls back to the visualization's own title |

**Output:**
```json
{
  "id": "d12abc...",
  "kind": "dashboard",
  "created_at": "2026-05-15T10:30:00Z",
  "updated_at": "2026-05-15T10:30:00Z",
  "attributes": {
    "id": "d12abc...",
    "schema_version": "v1",
    "title": "FlexLM License Overview",
    "panels": [
      {"id": "panel_0", "kind": "visualization", "viz_id": "0a9c8f...",
       "layout": {"x": 0, "y": 0, "w": 12, "h": 8}, "title_override": null}
    ],
    "tags": [],
    "created_at": "2026-05-15T10:30:00Z",
    "updated_at": "2026-05-15T10:30:00Z",
    "created_by": "alice"
  }
}
```

---

### get_dashboard
**Description:** Fetch a saved dashboard by id.

**Input Parameters:**
- `dashboard_id` (str, required): The dashboard id

**Output:** Same response shape as `create_dashboard`.

---

### list_dashboards
**Description:** List dashboards the caller can see, with pagination.

**Input Parameters:**
- `limit` (int, optional): Page size (server default 500, max 1000)
- `offset` (int, optional): Page offset (default 0)

**Output:**
```json
{"items": [{"id": "d12abc...", "kind": "dashboard", "attributes": {"...": "..."}}]}
```

---

### update_dashboard
**Description:** Patch a dashboard with a partial spec — same semantics as [`update_visualization`](#update_visualization). Send only the fields you want to change; anything you don't send is preserved. Note that lists (notably `panels`) are replaced wholesale by the patch, not merged element-wise — to add a single panel, resend the full updated `panels` list including the new entry.

**Input Parameters:**
- `dashboard_id` (str, required): The dashboard id
- `partial` (dict, required): Subset of the dashboard spec to merge in

**Sample Input:**
```json
{"title": "FlexLM Overview (Q3)"}
```

**Output:** The updated dashboard (same response shape as `create_dashboard`).

---

### delete_dashboard
**Description:** Delete a dashboard by id.

**Input Parameters:**
- `dashboard_id` (str, required): The dashboard id

**Output:**
```json
{"acknowledged": true}
```

---

### execute_dashboard
**Description:** Execute every panel in a dashboard in parallel via `ThreadPoolExecutor` and return per-panel layout + viz config + plot-ready rows in one call. Per-panel errors are isolated — one bad panel surfaces under that panel's `error` field; the rest still return.

**Input Parameters:**
- `dashboard_id` (str, required): The dashboard id
- `max_workers` (int, optional): Thread-pool size for the fan-out (default 16)

**Output:**
```json
[
  {
    "id": "panel_0",
    "kind": "visualization",
    "layout": {"x": 0, "y": 0, "w": 12, "h": 8},
    "title_override": null,
    "viz":  { "<full Visualization attributes>": "..." },
    "data": { "columns": [], "rows": [], "metadata": {} },
    "error": null
  },
  {
    "id": "panel_1",
    "kind": "visualization",
    "layout": {"x": 12, "y": 0, "w": 18, "h": 16},
    "title_override": null,
    "viz":  null,
    "data": null,
    "error": {"status": 500, "message": "SQL parse error: ..."}
  }
]
```
