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
  - `streaming`: whether to start the thread in streaming mode

** Sample Input: **
```json
{"name":"Detailed Dashboard","streaming":true}
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
- `message` (dict, required): The message object to add

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
