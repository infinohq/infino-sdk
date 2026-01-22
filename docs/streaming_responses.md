# Fino Streaming Response Format

This document describes the WebSocket message format when using Fino AI with **streaming mode enabled** (`streaming: true`).

## Overview

When streaming is enabled, Fino sends responses progressively via WebSocket as the AI processes your query. This allows you to:

- Show real-time progress to users
- Display partial results as they become available
- Build responsive, interactive chat interfaces

## Enabling Streaming Mode

Set `streaming: true` when creating a thread:

```python
config = {
    "name": "My Thread",
    "streaming": True,  # Enable streaming
    "sources": [{"index_name": "my_dataset", "connection_id": "infino"}]
}

response = sdk.request("POST", f"{endpoint}/_conversation/threads", {}, json.dumps(config), {})
thread_id = response["id"]
```

The thread response will confirm streaming is enabled:

```json
{
  "id": "d82458da-1415-4c46-8570-4c9ef13201d3",
  "streaming": true,
  ...
}
```

---

## Message Structure

All streaming messages follow this structure:

```json
{
  "content": {
    "type": "<message_type>",
    ...
  },
  "role": "assistant",
  "created_at": "2026-01-22T09:00:16.466638+00:00"
}
```

**Key fields:**
- `content` - Dictionary containing the message payload
- `content.type` - The message type (see below)
- `role` - Always `"assistant"` for AI responses
- `created_at` - ISO 8601 timestamp

---

## Message Types

There are **four main message types** you need to handle:

| Type | Purpose | Action |
|------|---------|--------|
| `update` | Progress/status updates | Optional: Display to show AI is working |
| `partial` | Streaming content results | **Required**: Handle and display to user |
| `EOM` | End of message | **Required**: Stop listening, response complete |
| `error` | Error occurred | **Required**: Handle error, stop listening |

Additionally, you may receive **heartbeat** messages (keep-alive) which should be ignored.

---

## Type 1: `update` (Progress Messages)

**Purpose:** Shows what the AI is doing at each processing step.

**Structure:**
```json
{
  "content": {
    "type": "update",
    "sender": "router",
    "message": "Gathering sources..."
  },
  "role": "assistant",
  "created_at": "2026-01-22T09:00:16.466638+00:00"
}
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Always `"update"` |
| `sender` | string | The AI component sending the update |
| `message` | string | Human-readable status message |

**Common senders:**
| Sender | Description |
|--------|-------------|
| `router` | Initial routing and source gathering |
| `spell_checker` | Query spelling validation |
| `history_analyzer` | Analyzing conversation context |
| `intent_classifier` | Determining query intent (data_query, greeting, etc.) |
| `connection_selector` | Selecting the best data source |
| `query_type_selector` | Choosing query strategy (QueryDSL, SQL, etc.) |
| `query_planner` | Planning query execution |
| `fact_retriever` | Executing query and generating response |
| `visualization_agent` | Analyzing data for charting |
| `suggestion_agent` | Generating follow-up suggestions |

**Handling:** Optional. Display these to show users the AI is actively working.

```python
if msg_type == "update":
    sender = content.get("sender", "")
    message = content.get("message", "")
    print(f"[{sender}] {message}")  # Optional: show to user
```

---

## Type 2: `partial` (Streaming Content)

**Purpose:** Delivers actual results progressively as they become available.

**Structure:**
```json
{
  "content": {
    "type": "partial",
    "sender": "fact_retriever",
    "sub_type": "summary",
    "value": "### Results\n\nThere are **5** products..."
  },
  "role": "assistant",
  "created_at": "2026-01-22T09:00:56.365315+00:00"
}
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Always `"partial"` |
| `sender` | string | The AI component sending the partial result |
| `sub_type` | string | The kind of content being streamed |
| `value` | varies | The actual content (type depends on `sub_type`) |

### Sub-Types

The `sub_type` field determines what kind of content is in `value`:

| sub_type | value type | Description |
|----------|------------|-------------|
| `summary` | `string` | Text response (markdown formatted) |
| `data` | `object` | Query results as `{"df": [...]}` |
| `querydsl` | `object` | The generated QueryDSL query |
| `sql` | `string` | The generated SQL query |
| `chart` | `object` | Chart/visualization configuration |
| `sources` | `array` | Data sources being queried |
| `smart_suggestion` | `array` | List of follow-up question suggestions |

### Sub-Type Details

#### `summary` (string)

The main text response, typically in Markdown format.

```json
{
  "type": "partial",
  "sender": "fact_retriever",
  "sub_type": "summary",
  "value": "### Inventory Overview\n\n* **Total Catalog Size:** There are currently **5** products available."
}
```

**Handling:** Display this text to the user. This is the primary response content.

#### `data` (object)

Query results in a structured format.

```json
{
  "type": "partial",
  "sender": "fact_retriever",
  "sub_type": "data",
  "value": {
    "df": [
      {"result_count": 5}
    ]
  }
}
```

**Handling:** Use this for displaying tables, charts, or raw data.

#### `querydsl` (object)

The generated QueryDSL query that was executed.

```json
{
  "type": "partial",
  "sender": "fact_retriever",
  "sub_type": "querydsl",
  "value": {
    "query": {"match_all": {}},
    "size": 0,
    "track_total_hits": true
  }
}
```

**Handling:** Optional. Display for debugging or transparency.

#### `sql` (string)

The generated SQL query that was executed.

```json
{
  "type": "partial",
  "sender": "sql_generator",
  "sub_type": "sql",
  "value": "SELECT * FROM orders WHERE status = 'pending'"
}
```

**Handling:** Optional. Display for debugging or transparency.

#### `chart` (object)

Chart/visualization configuration for rendering graphs.

```json
{
  "type": "partial",
  "sender": "visualization_agent",
  "sub_type": "chart",
  "value": {
    "series": [
      {"name": "Sales", "data": [10, 20, 30]}
    ],
    "xAxis": {
      "categories": ["Jan", "Feb", "Mar"]
    },
    "chart": {
      "type": "bar"
    }
  }
}
```

**Handling:** Use this to render charts/visualizations. The structure follows common charting library formats.

#### `sources` (array)

The data sources being queried.

```json
{
  "type": "partial",
  "sender": "router",
  "sub_type": "sources",
  "value": [
    {"index_name": "streaming_demo_products", "connection_id": "infino"}
  ]
}
```

**Handling:** Optional. Display to show which datasets are being used.

#### `smart_suggestion` (array of strings)

Suggested follow-up questions.

```json
{
  "type": "partial",
  "sender": "collector_agent",
  "sub_type": "smart_suggestion",
  "value": [
    "What are the names of all the products we have?",
    "How many products are currently in stock?",
    "What is the average price of our products?"
  ]
}
```

**Handling:** Display as clickable suggestions for the user.

---

## Type 3: `EOM` (End of Message)

**Purpose:** Signals that the response is complete.

**Structure:**
```json
{
  "content": {
    "type": "EOM",
    "trace_id": "07d7ea30-96de-4836-9d3a-0340a3ec8d28"
  },
  "role": "assistant",
  "created_at": "2026-01-22T09:00:59.936186+00:00"
}
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Always `"EOM"` (End of Message) |
| `trace_id` | string | Unique identifier for this response (useful for debugging) |

**Handling:** **Required.** Stop listening for messages. The response is complete.

```python
if msg_type == "EOM":
    print("Response complete!")
    break  # Exit the message loop
```

---

## Type 4: `error` (Error Messages)

**Purpose:** Indicates an error occurred during processing.

**Structure:**
```json
{
  "type": "error",
  "summary": "An error occurred",
  "data": {
    "error": "Connection timeout while querying data source"
  }
}
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Always `"error"` |
| `summary` | string | Human-readable error summary |
| `data` | object | Error details containing `error` message |

**Note:** Error messages have a different structure - they do NOT have a `content` wrapper.

**Handling:** **Required.** Display error to user and stop listening.

```python
# Check for error (no "content" wrapper, similar to heartbeat)
if data.get("type") == "error":
    error_summary = data.get("summary", "Unknown error")
    error_detail = data.get("data", {}).get("error", "")
    print(f"Error: {error_summary} - {error_detail}")
    break  # Stop listening
```

---

## Heartbeat Messages

You may receive keep-alive messages. These have a different structure (no `content` wrapper):

```json
{
  "type": "heartbeat",
  "message": "keep-alive"
}
```

**Handling:** Ignore these messages.

```python
# Check for heartbeat first (different structure)
if data.get("type") == "heartbeat":
    continue  # Ignore and wait for next message
```

---

## Connection Errors

The WebSocket connection may close unexpectedly due to:

- **Keepalive ping timeout**: The websockets library sends periodic ping frames. If the server doesn't respond within the timeout, the connection closes with error code 1011.
- **Network issues**: Temporary network interruptions
- **Server-side timeout**: The server may close idle connections

**Example error:**
```
websockets.exceptions.ConnectionClosedError: sent 1011 (internal error) keepalive ping timeout; no close frame received
```

**Handling:** Catch `ConnectionClosed` or `ConnectionClosedError` from the `websockets.exceptions` module:

```python
from websockets.exceptions import ConnectionClosed

while True:
    try:
        response = await asyncio.wait_for(ws.recv(), timeout=180.0)
    except ConnectionClosed as e:
        print(f"Connection closed: {e}")
        break
    except asyncio.TimeoutError:
        print("Timeout waiting for response")
        break
    
    # Process response...
```

---

## Complete Example

Here's a complete Python example for handling streaming responses.

> **Try it yourself:** See [`examples/fino_streaming_chat.py`](../examples/fino_streaming_chat.py) for a fully runnable example that you can execute with:
> ```bash
> export INFINO_ACCESS_KEY="your_key"
> export INFINO_SECRET_KEY="your_secret"
> python examples/fino_streaming_chat.py
> ```

```python
import json

async def handle_streaming_response(ws):
    """Handle streaming responses from Fino AI."""
    
    summary_text = ""
    data_result = None
    chart_config = None
    sql_query = None
    querydsl_query = None
    suggestions = []
    error = None
    
    while True:
        response = await ws.recv()
        data = json.loads(response)
        
        # ----- HEARTBEAT: Keep-alive (no "content" wrapper) -----
        if data.get("type") == "heartbeat":
            continue
        
        # ----- ERROR: Error occurred (no "content" wrapper) -----
        if data.get("type") == "error":
            error_summary = data.get("summary", "Unknown error")
            error_detail = data.get("data", {}).get("error", "")
            error = f"{error_summary}: {error_detail}"
            print(f"Error: {error}")
            break
        
        content = data.get("content", {})
        msg_type = content.get("type", "")
        
        # ----- UPDATE: Progress messages -----
        if msg_type == "update":
            sender = content.get("sender", "")
            message = content.get("message", "")
            print(f"[{sender}] {message}")  # Optional
        
        # ----- PARTIAL: Streaming content -----
        elif msg_type == "partial":
            sub_type = content.get("sub_type", "")
            value = content.get("value")
            
            if sub_type == "summary":
                # value is a string (markdown text)
                summary_text = value
                print(value)
            
            elif sub_type == "data":
                # value is {"df": [...]}
                data_result = value
            
            elif sub_type == "chart":
                # value is chart configuration object
                chart_config = value
            
            elif sub_type == "sql":
                # value is SQL query string
                sql_query = value
                print(f"SQL: {value}")
            
            elif sub_type == "querydsl":
                # value is QueryDSL query object
                querydsl_query = value
                print(f"QueryDSL: {json.dumps(value)}")
            
            elif sub_type == "smart_suggestion":
                # value is a list of strings
                suggestions = value
            
            elif sub_type == "sources":
                # value is a list of source objects
                print(f"Sources: {value}")
        
        # ----- EOM: End of message -----
        elif msg_type == "EOM":
            print("Response complete!")
            break
    
    return {
        "summary": summary_text,
        "data": data_result,
        "chart": chart_config,
        "sql": sql_query,
        "querydsl": querydsl_query,
        "suggestions": suggestions,
        "error": error
    }
```

---

## Message Flow Diagram

```
User sends query
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│                    STREAMING RESPONSE                         │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────┐   Multiple "update" messages showing progress   │
│  │ update  │ ──► [router] Gathering sources...               │
│  └─────────┘     [spell_checker] Checking spelling...        │
│       │          [intent_classifier] Analyzing query...      │
│       │          [fact_retriever] Executing query...         │
│       ▼                                                       │
│  ┌─────────┐   Multiple "partial" messages with results      │
│  │ partial │ ──► sub_type: "summary" (text response)         │
│  └─────────┘     sub_type: "data" (query results)            │
│       │          sub_type: "sql" (SQL query)                 │
│       │          sub_type: "querydsl" (QueryDSL query)       │
│       │          sub_type: "chart" (visualization config)    │
│       │          sub_type: "smart_suggestion" (follow-ups)   │
│       ▼                                                       │
│  ┌─────────┐   Single "EOM" message                          │
│  │  EOM    │ ──► Response complete, stop listening           │
│  └─────────┘                                                  │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

## Quick Reference

```python
# Message type handling (check top-level type first for heartbeat/error)
if data.get("type") == "heartbeat":
    continue  # Ignore keep-alive

if data.get("type") == "error":
    print(f"Error: {data.get('summary')} - {data.get('data', {}).get('error')}")
    break  # Stop on error

content = data.get("content", {})
msg_type = content.get("type", "")

if msg_type == "update":
    # Optional: Show progress
    print(f"[{content['sender']}] {content['message']}")

elif msg_type == "partial":
    sub_type = content.get("sub_type", "")
    value = content.get("value")
    
    if sub_type == "summary":           # value: string (markdown)
        display_text(value)
    elif sub_type == "data":            # value: {"df": [...]}
        display_data(value)
    elif sub_type == "chart":           # value: chart config object
        render_chart(value)
    elif sub_type == "sql":             # value: string (SQL query)
        log_sql(value)
    elif sub_type == "querydsl":        # value: query object
        log_query(value)
    elif sub_type == "smart_suggestion": # value: list of strings
        show_suggestions(value)
    elif sub_type == "sources":         # value: list of sources
        log_sources(value)

elif msg_type == "EOM":
    break  # Done!
```

---

## See Also

- [SDK Methods Documentation](./sdk_methods.md) - Full API reference
- [WebSocket Chat Example](../examples/fino_websocket_chat.py) - Non-streaming example
- [Streaming Chat Example](../examples/fino_streaming_chat.py) - Streaming example
