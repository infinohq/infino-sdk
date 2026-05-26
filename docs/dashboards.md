# Dashboards & Visualizations

Build, save, execute, and render charts and dashboards programmatically.

A **visualization** is a saved chart definition: where to get the data (a SQL query against one of your datasets) and how to render it (chart type, axis mapping, optional formatting). Each visualization is identified by an id you can fetch, update, or execute on demand.

A **dashboard** is an ordered list of panels. Each panel either references a saved visualization or carries inline content (markdown / divider). Layout is a 48-column CSS grid, with per-panel `{x, y, w, h}` placement.

The SDK is renderer-agnostic — `execute_*` returns plain `{columns, rows, metadata}`, and `to_echarts_option` turns a visualization plus its rows into a ready-to-render ECharts option dict. You can also feed those rows to plotly, matplotlib, pandas, or your own renderer.

## Quickstart

**Prereq:** a visualization needs a dataset to query. Replace `license_events` below with the name of one of your own datasets — list them with `sdk.get_datasets()` and inspect columns with `sdk.get_dataset_schema("<name>")`. If you're starting from scratch, create a dataset and upload data first; see the [main README](../README.md) for ingestion examples.

The smallest working flow — create a chart, run its query, get a ready-to-render spec:

```python
from infino_sdk import InfinoSDK

sdk = InfinoSDK(access_key, secret_key, "https://api.infino.ws")

# 1. Define and save a chart.
viz = sdk.create_visualization({
    "title": "Top denied features",
    "source": {
        "kind": "sql",
        "index": "license_events",
        "sql": {
            "raw_query": (
                "SELECT feature, COUNT(*) AS denials "
                "FROM license_events "
                "WHERE event_type = 'DENIED' "
                "GROUP BY feature "
                "ORDER BY denials DESC LIMIT 10"
            ),
        },
    },
    "chart": {"type": "bar"},
})

# 2. Run the SQL and get plot-ready rows.
data = sdk.execute_visualization(viz["id"])
# data = {"columns": [{"name": "feature", "type": "string"}, ...],
#         "rows":    [{"feature": "synopsys_vcs", "denials": 1284}, ...],
#         "metadata": {...}}

# 3. Turn it into a chart spec. Pure function — no network call.
spec = sdk.to_echarts_option(viz, data)
# spec["option"] is plain ECharts JSON you can pass to echarts.setOption(...)
# in the browser, or feed to pyecharts in Python.
```

Then bundle one or more saved visualizations into a dashboard:

```python
dash = sdk.create_dashboard({
    "title": "License Overview",
    "panels": [{"viz_id": viz["id"]}],   # layout auto-flows when omitted
})

# Execute every panel in parallel — one call instead of an N+1 loop.
panels = sdk.execute_dashboard(dash["id"])
for p in panels:
    if p["error"]:
        continue
    spec = sdk.to_echarts_option(p["viz"], p["data"])
    # render spec into your page at p["layout"]
```

The full end-to-end script (creating five real charts, bundling them into a dashboard, and rendering a layout-aware HTML page via CSS Grid) lives in [examples/dashboards/](../examples/dashboards/).

## Builder mode — no SQL required

The Quickstart above writes a `raw_query` by hand. That's the right choice when you need full SQL power, but it puts the burden of GROUP BY / aggregation / dialect-quoting on the caller. **Builder mode** lets you describe the chart in terms of columns + an aggregation, and the gateway generates the SQL for you — including correct dialect quoting for connector-backed sources (MySQL, BigQuery, Snowflake, etc.).

Same `create_visualization` call; just omit `source.sql.raw_query` and set `mapping` + `aggregation_type` instead:

```python
viz = sdk.create_visualization({
    "title": "Top denied features",
    "source": {
        "kind": "sql",
        "index": "license_events",
        # raw_query omitted — gateway generates it
        "sql": {"limit": 10},
    },
    "chart": {"type": "bar"},
    "mapping": {"x": "feature_name", "y": ["denials"], "series_split_by": None},
    "aggregation_type": "count",
})
```

The gateway emits SQL equivalent to:

```sql
SELECT feature_name, COUNT(*) as count FROM "license_events"
GROUP BY feature_name ORDER BY feature_name LIMIT 10
```

For multi-series charts add `mapping.series_split_by`; for connector-backed sources include `source.connector_id` (e.g. `"mysql"`, `"bigquery"`) so identifiers are quoted in the right dialect.

### Aggregation cheat sheet

Set `aggregation_type` to one of:

| Value | Emits | Use when |
|-------|-------|----------|
| `count` | `COUNT(*) as count` | counting rows that match (events, errors, denials) |
| `sum` | `SUM(y) as sum_y` | each row contributes a quantity (revenue, units, bytes) |
| `avg` | `AVG(y) as avg_y` | typical value across rows (latency, price, temperature) |
| `none` | no aggregation | raw rows for scatter / table view |

Picking the wrong one rarely *breaks* the query, but `count` on a numeric column or `sum` on a category column produces nonsense charts. Match the function to what each row represents.

### When to use which mode

| Builder mode | Raw SQL |
|--------------|---------|
| Single-table aggregations | Multi-table JOINs |
| Standard `GROUP BY` + chart axes | Window functions, CTEs, subqueries |
| Cross-dialect (gateway handles quoting) | Dialect-specific syntax you control |
| 80% of dashboard panels | Hand-tuned analytical queries |

Mix freely within a dashboard.

### Top-N pattern

The classic "top 10 customers by GMV" pattern uses `source.sql.order_by`
to override the default `ORDER BY <x-axis>`. The `column` field references
the **aggregation alias** the gateway generates — `{function}_{column}` for
`sum`/`avg`, or literal `count` when no Y-axis is provided.

```python
# Top 10 customers by total GMV (BigQuery)
viz = sdk.create_visualization({
    "source": {
        "kind": "sql",
        "index": "Customer_PnL_v2",
        "connector_id": "bigquery",
        "sql": {
            "metrics": [{"function": "sum", "column": "Cust_SKU_GMV"}],
            "order_by": [{"column": "sum_Cust_SKU_GMV", "direction": "desc"}],
            "limit": 10,
        },
    },
    "chart": {"type": "bar"},
    "mapping": {"x": "Customer_Name", "y": ["Cust_SKU_GMV"]},
})
# Gateway emits:
#   SELECT `Customer_Name`, SUM(`Cust_SKU_GMV`) as `sum_Cust_SKU_GMV`
#   FROM `Customer_PnL_v2`
#   GROUP BY `Customer_Name`
#   ORDER BY `sum_Cust_SKU_GMV` DESC LIMIT 10
```

The alias name to reference in `order_by`:

| Aggregation | Alias |
|-------------|-------|
| `count` (or no Y-axis) | `count` |
| `sum` on column `revenue` | `sum_revenue` |
| `avg` on column `latency_ms` | `avg_latency_ms` |

Direction defaults to `asc`; invalid values clamp to `asc` (caller typos
won't propagate as SQL). Multiple entries are supported and preserved in
spec order:

```python
"order_by": [
    {"column": "region", "direction": "asc"},
    {"column": "sum_revenue", "direction": "desc"},
],
```

For dimensions that aren't aggregated (scatter plots, raw row mode),
`order_by` references real schema columns directly:

```python
"order_by": [{"column": "@timestamp", "direction": "desc"}],
```

## SDK surface

### Visualization lifecycle

- **`create_visualization(spec)`** — Create a chart. The server fills mapping / options / tags / limit when you omit them. Two minimum bodies:
  - **Raw SQL:** `{title, source: {kind, index, sql: {raw_query}}, chart: {type}}`
  - **Builder mode:** `{title, source: {kind, index, sql: {limit?}}, chart: {type}, mapping: {x, y[]}, aggregation_type}` — gateway generates the SQL. See [Builder mode](#builder-mode--no-sql-required).
- **`get_visualization(viz_id)`** — Fetch one. The chart definition lives in the `attributes` field of the response; `id`, `created_at`, `updated_at` sit alongside it as response metadata.
- **`list_visualizations(limit=None, offset=None)`** — Returns `{"items": [...]}`. Server defaults: `limit=500` (max 1000), `offset=0`.
- **`update_visualization(viz_id, partial)`** — Send only the fields you want to change. Anything you don't send is preserved. Send a field as `null` to unset it. Lists are replaced wholesale (not merged element-wise). `id`, `schema_version`, `created_at`, and `created_by` are immutable; the server ignores attempts to overwrite them. *(Wire format: RFC 7396 JSON Merge Patch.)*
- **`delete_visualization(viz_id)`** — Delete by id.

### Visualization execution

- **`execute_visualization(viz_id, filters=None, time_range=None)`** — Run the saved SQL and get plot-ready rows: `{"columns": [{"name", "type"}, ...], "rows": [...], "metadata": {...}}`. Each column's `type` is normalised to `string` / `number` / `boolean` / `date` / `null`, so the renderer can pick axis kinds without re-sniffing.
  - `filters=` (optional) — list of filter dicts AND-merged into the executed SQL on top of any filters saved on the viz. See [`filters[*]`](#filter-fields) for the dict shape and supported operators.
  - `time_range=` (optional) — `{"from", "to"}` dict applied as a synthetic `is_between` filter on the viz's time column (`source.sql.time_column`, default `@timestamp`). See [Time-range injection](#time-range-injection).
  - `metadata.filters_applied` / `metadata.filters_skipped` surface which filters made it into the dispatched SQL vs. which the rewriter couldn't safely inject (parser edge cases, etc.). Unrecognised filters never fail the call — the original SQL still runs.
- **`to_echarts_option(viz, data)`** — Pure function (no network call). Turns the saved visualization plus its rows into one of three render-ready shapes depending on what makes sense for the data:
  - **`kind == "echarts"`** — `result["option"]` is plain ECharts JSON. Pass it straight to `echarts.setOption(...)` in the browser, or to pyecharts in Python. Covers `bar`, `horizontalBar`, `line`, `area`, `pie`, `heatmap`, `scatter`.
  - **`kind == "table"`** — `result["columns"]` and `result["rows"]` for inline HTML / pandas rendering. Returned when `visualization_mode == "table"` or when the data doesn't fit the declared chart type.
  - **`kind == "metric"`** — `result["value"]` is the single aggregated number with optional `result["formatting"]` (`prefix`, `suffix`, `decimals`, `abbreviate`, `thousands_separator`). Returned when `visualization_mode == "metric"` or `chart.type == "metric" | "gauge"`.

  Check `kind` and render accordingly.

### Time-range injection

Apply a time window at execute time without baking it into the SQL:

    data = sdk.execute_visualization(viz_id, time_range={
        "from": "2026-04-01T00:00:00Z",
        "to":   "2026-05-01T00:00:00Z",
    })

Server-side this becomes an `is_between` filter on the viz's time column
(`source.sql.time_column`, default `@timestamp`). Accepts ISO-8601 strings or
epoch-ms numbers (UTC). Combined with `filters=` they AND-merge into the
executed SQL.

Same kwarg on `execute_dashboard` applies the window to every panel in the
fanout:

    panels = sdk.execute_dashboard(dash_id, time_range={
        "from": "2026-04-01T00:00:00Z",
        "to":   "2026-05-01T00:00:00Z",
    })

### Dashboard lifecycle

- **`create_dashboard(spec)`** — Create a dashboard. Minimum body is `{"title"}`; `panels` defaults to `[]`. See [Layout](#layout) for what `w`/`h` mean.
- **`get_dashboard(dashboard_id)`** — Fetch one.
- **`list_dashboards(limit=None, offset=None)`** — Returns `{"items": [...]}` with the same pagination as `list_visualizations`.
- **`update_dashboard(dashboard_id, partial)`** — Same patch semantics as `update_visualization`. Note that `panels` is a list and gets replaced wholesale by the patch — to add one panel, resend the full updated list including the new entry.
- **`delete_dashboard(dashboard_id)`** — Delete by id.

### Dashboard execution

- **`execute_dashboard(dashboard_id, max_workers=16, filters=None, time_range=None)`** — Execute every panel in parallel and return per-panel layout + viz definition + plot-ready rows in one call. Per-panel errors are isolated: if one panel's SQL fails (typo, deleted column, dataset gone), only that panel's `error` field is populated; the rest still return. Lets you ship a partially-broken dashboard without taking the whole page down.

  For a 16-panel dashboard, this replaces 33 sequential HTTP calls (`get_visualization` + `execute_visualization` per panel) with a single SDK call that fans out under the hood.

  `filters=` (optional) is applied to **every panel** — same shape as `execute_visualization`'s kwarg, AND-merged into each panel's SQL via the server-side rewriter. Useful for dashboard-wide filter chips (e.g. "show only product = X across all 16 charts").

  `time_range=` (optional) is applied to **every panel** — same `{"from", "to"}` shape as the `execute_visualization` kwarg. Backs the dashboard-level time picker.

## Layout

Dashboards use a 48-column CSS grid. Each panel places itself with `{x, y, w, h}` (in grid units, not pixels):

- `x`, `y` — top-left corner (0-indexed, `x` is column, `y` is row)
- `w` — width in columns (1–48)
- `h` — height in row units (1 row unit ≈ 22px in the reference renderer)

Common sizes:

| What | `w` × `h` |
|------|-----------|
| Single-number metric card | `12 × 8` |
| Half-width chart | `24 × 16` |
| Third-width chart | `16 × 16` |
| Quarter-width chart | `12 × 16` |
| Full-width chart (header strip) | `48 × 12` |
| Full-width chart (main body) | `48 × 20` |

Sketch of a typical 3-panel top row:

```
   col 0          col 12              col 30                col 48
y=0 +-----------+-------------------+---------------------+
    |  metric   |    bar chart      |    pie chart        |
    |  12 × 8   |    18 × 16        |    18 × 16          |
y=8 +-----------+                   |                     |
    |  (free)   |                   |                     |
y=16+-----------+-------------------+---------------------+
```

You can also **omit `layout` on every panel** — the server auto-flows panels into a 2-column grid using sensible defaults. Mix implicit and explicit layouts freely.

## Request and Response Formats

The API wraps each saved object in a small response shape:

```json
{
  "id": "0a9c8f...",
  "kind": "visualization",
  "created_at": "2026-05-15T10:30:00Z",
  "updated_at": "2026-05-15T10:30:00Z",
  "attributes": { "...the visualization itself..." }
}
```

`id` / `created_at` / `updated_at` are response metadata; the visualization (or dashboard) you sent is in `attributes`. The same shape is returned by `create_*`, `get_*`, and `update_*`.

### `create_visualization()` Request

**HTTP Method:** POST  
**Endpoint:** `/visualizations`

Minimum body:

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

Every other field is optional and server-defaulted. See [Configuration reference](#configuration-reference) below for the complete list of fields you can pass, their types, defaults, and effects.

**Response:**

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
    "mapping": {"x": null, "y": [], "series_split_by": null},
    "options": {"metric_formatting": null},
    "visualization_mode": "chart",
    "tags": [],
    "created_at": "2026-05-15T10:30:00Z",
    "updated_at": "2026-05-15T10:30:00Z",
    "created_by": "alice"
  }
}
```

### `execute_visualization()` Response

**HTTP Method:** POST  
**Endpoint:** `/visualizations/{viz_id}/data`  
**Body:** `{}` — optionally pass `filters` (list of filter dicts) and/or `time_range` (`{"from", "to"}`); both are AND-merged into the executed SQL via the server-side rewriter.

```json
{
  "columns": [
    {"name": "feature", "type": "string"},
    {"name": "denials", "type": "number"}
  ],
  "rows": [
    {"feature": "synopsys_vcs", "denials": 1284},
    {"feature": "cadence_innovus", "denials": 902}
  ],
  "metadata": {
    "source_kind": "sql",
    "row_count": 2,
    "truncated": false,
    "took_ms": 47,
    "executed_query": "SELECT feature, ..."
  }
}
```

Column `type` is normalised to `string` / `number` / `boolean` / `date` / `null`.

### `create_dashboard()` Request

**HTTP Method:** POST  
**Endpoint:** `/dashboards`

```json
{
  "title": "License Overview",
  "panels": [
    {"viz_id": "0a9c8f...", "layout": {"x": 0,  "y": 0,  "w": 12, "h": 8}},
    {"viz_id": "1b8d7e...", "layout": {"x": 12, "y": 0,  "w": 18, "h": 16}},
    {"viz_id": "2c7e6d...", "layout": {"x": 30, "y": 0,  "w": 18, "h": 16}}
  ]
}
```

Panel fields:

| Field | Type | Notes |
|-------|------|-------|
| `kind` | `"visualization"` \| `"markdown"` \| `"divider"` | Defaults to `"visualization"` |
| `viz_id` | string | Required for visualization panels |
| `content` | string | Required for markdown panels |
| `layout.x` / `layout.y` / `layout.w` / `layout.h` | integer | 48-column grid; see [Layout](#layout) |
| `title_override` | string \| null | Display title; falls back to the visualization's own title |

### `execute_dashboard()` Response

The SDK fans out to `/visualizations/{viz_id}/data` per panel under the hood and returns one list:

```json
[
  {
    "id": "panel_0",
    "kind": "visualization",
    "layout": {"x": 0, "y": 0, "w": 12, "h": 8},
    "title_override": null,
    "viz":  { "...full visualization definition..." },
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

## Chart types

`chart.type` and what `to_echarts_option` returns:

| `chart.type` | `to_echarts_option` `kind` | Notes |
|-------------|----------------------------|-------|
| `bar`, `horizontalBar`, `line`, `area`, `pie`, `heatmap`, `scatter` | `echarts` | Plain ECharts option dict |
| `metric`, `gauge` | `metric` | Single-value display; respects `options.metric_formatting` |
| any (with `visualization_mode == "table"`) | `table` | Raw `{columns, rows}` for HTML / pandas |

**Picking columns.** `to_echarts_option` uses `viz.mapping.x`, `viz.mapping.y`, and `viz.mapping.series_split_by` to decide which columns become which axes. If `mapping` is empty it falls back to "first non-numeric column → X, first numeric column → Y" — so you can omit `mapping` for simple bar / line charts.

**Sorting.** Axis values are sorted numeric-aware (no `"10"` before `"9"` surprises).

**Styling.** Colors, theme, tooltip formatters, and number formatting are intentionally minimal in `to_echarts_option`. Deep-merge your theme on top in your renderer, or apply `options.metric_formatting` (`prefix`, `suffix`, `decimals`, `abbreviate`, `thousands_separator`) yourself.

## Configuration reference

Every field a visualization spec can carry. Only `title`, `source.kind`, `source.index`, `chart.type`, and (for `source.kind == "sql"`) `source.sql.raw_query` are required — everything else has a server default. A runnable example exercising the optional fields lives at [`examples/dashboards/advanced_chart_config.py`](../examples/dashboards/advanced_chart_config.py).

### Top-level fields

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `title` | string | (required) | Display title |
| `description` | string \| null | `null` | Free-form description shown in list views and detail panes |
| `source` | object | (required) | Data source — see [`source.*`](#source-fields) |
| `chart.type` | enum | (required) | `bar`, `horizontalBar`, `line`, `area`, `scatter`, `pie`, `heatmap`, `metric`, `gauge` |
| `visualization_mode` | enum | `"chart"` | `"chart"` renders as `chart.type`; `"table"` returns raw rows; `"metric"` returns a single scalar |
| `mapping` | object | `{x: null, y: [], series_split_by: null}` | See [`mapping.*`](#mapping-fields). **In Builder mode, drives SQL generation.** |
| `aggregation_type` | enum \| null | `null` | `count`, `sum`, `avg`, `none`. **Used in Builder mode** to pick the aggregation function. See [Aggregation cheat sheet](#aggregation-cheat-sheet). |
| `options` | object | all `null` | Chart-specific options — see [`options.*`](#options-fields) |
| `filters` | array | `[]` | Saved filters — see [`filters[*]`](#filter-fields). **AND-merged into the executed SQL at runtime** alongside any `filters=` kwarg you pass to `execute_visualization`. |
| `time_range` | object \| null | `null` | Saved time range — see [`time_range`](#time-range). **Applied at execute time** as a synthetic `is_between` filter on `source.sql.time_column` (default `@timestamp`). A `time_range=` kwarg on `execute_visualization` / `execute_dashboard` overrides the saved value for that call. |
| `render` | object \| null | `null` | Escape hatch for full ECharts JSON — see [`render`](#render-escape-hatch) |
| `tags` | string[] | `[]` | Free-form tags for filtering / grouping in list views |
| `extensions` | object \| null | omitted | Free-form metadata blob; the server stores it but does not interpret it |

### `source.*` fields

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `source.kind` | enum | (required) | `"sql"` (currently the only kind wired through `execute_*`), `"querydsl"`, `"promql"` |
| `source.index` | string | (required) | Dataset name (e.g. `"license_events"`) |
| `source.connection_id` | string \| null | `null` | For connector-backed sources (Snowflake, BigQuery, etc.) |
| `source.connector_id` | string \| null | `null` | The connector type id when `connection_id` is set |
| `source.sql` | object \| null | `null` (set when `kind == "sql"`) | See below |
| `source.dsl` | object \| null | `null` (set when `kind == "querydsl"`) | Reserved — not yet wired through |
| `source.promql` | object \| null | `null` (set when `kind == "promql"`) | Reserved — not yet wired through |

When `source.kind == "sql"`:

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `source.sql.raw_query` | string \| null | `null` | The SQL string. **Required unless using Builder mode** (set `mapping` + `aggregation_type` instead — the gateway generates SQL from those). |
| `source.sql.time_column` | string \| null | `null` (server falls back to `@timestamp`) | Column used by the runtime time-range injection. Set explicitly for connector vizzes whose time field is not `@timestamp` (e.g. `created_at` for BigQuery, `_time` for Splunk). |
| `source.sql.limit` | integer | `50` | Server-side row cap. **Ignored if `raw_query` already has `LIMIT`** |
| `source.sql.offset` | integer | `0` | Server-side row offset (paginated execution) |
| `source.sql.dimensions` | array | `[]` | Reserved for future builder-mode extensions (richer dimension specs) |
| `source.sql.metrics` | array | `[]` | Builder-mode aggregation spec. Each entry: `{id, function, column, alias?, custom_expression?}`. `function` is one of `count` / `sum` / `avg` / `none`. The gateway reads `metrics[0]` to pick the aggregation; when omitted, defaults to `COUNT(*) as count`. |
| `source.sql.order_by` | array | `[]` | Builder-mode ORDER BY spec. Each entry: `{column, direction}` with `direction ∈ {asc, desc}`. `column` may be a real schema column OR an aggregation alias the gateway generates (`count`, `sum_<col>`, `avg_<col>`). Falls back to `ORDER BY <x-axis>` when omitted. See [Top-N pattern](#top-n-pattern). |

### `mapping.*` fields

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `mapping.x` | string \| null | `null` | Column name for the X axis (or category in pie). Falls back to "first non-numeric column" when `null` |
| `mapping.y` | string[] | `[]` | One or more column names for Y / value series. Falls back to "first numeric column" when empty |
| `mapping.series_split_by` | string \| null | `null` | Column to split the series by. **Required for `heatmap`** — the fallback picker can't infer it |

### `options.*` fields

All option fields default to `null` and only apply when relevant for the chart type.

| Field | Type | Applies to | Effect |
|-------|------|------------|--------|
| `options.legend.show` | boolean | all | Whether to render a legend |
| `options.legend.position` | enum | all | `"top"` \| `"right"` \| `"bottom"` \| `"left"` |
| `options.bar_max_width` | integer | `bar`, `horizontalBar` | Pixel cap for individual bars (prevents huge slabs in wide panels) |
| `options.pie_donut_ratio` | number | `pie` | `0.0` = solid pie; `> 0.0` = donut with hole of that ratio (`0.55` is a common donut look) |
| `options.metric_formatting.prefix` | string | `metric`, `gauge` | Rendered before the value (e.g. `"$"`) |
| `options.metric_formatting.suffix` | string | `metric`, `gauge` | Rendered after the value (e.g. `"/yr"`, `"%"`) |
| `options.metric_formatting.decimals` | integer | `metric`, `gauge` | Round to this many decimal places |
| `options.metric_formatting.thousands_separator` | boolean | `metric`, `gauge` | Insert `,` every 3 digits |
| `options.metric_formatting.abbreviate` | boolean | `metric`, `gauge` | `true` → `184K` instead of `184,250` |

### `filters[*]` fields

Filters are **AND-merged into the executed SQL** by the server-side rewriter. Two places filters can live, both applied together at execute time:

1. **Saved on the visualization** — set `filters` in the create/update spec. Travels with the viz forever.
2. **Runtime, per-call** — pass `filters=` to `execute_visualization` / `execute_dashboard`. Useful for filter chips that apply to a single render. Same dict shape.

When both are present they're merged (request filters win on `field` collision).

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `filters[].id` | string | auto-uuid via SDK | Stable id for this filter. The SDK auto-fills a uuid4 hex when omitted; only matters if you need to reference the same filter across update calls. |
| `filters[].field` | string | (required) | Column or field name — **raw, no quoting** (see note below) |
| `filters[].operator` | enum | (required) | `is`, `is_not`, `is_one_of`, `is_not_one_of`, `is_between`, `is_not_between`, `exists`, `does_not_exist` |
| `filters[].value` | any | (required) | Operand value; shape depends on the operator (`is_between` takes `[lo, hi]` or `{from, to}`) |
| `filters[].enabled` | boolean | `true` | Whether this filter is active |
| `filters[].is_time_filter` | boolean | `false` | Mark filters that target the time column (typically `@timestamp` for native datasets) |
| `filters[].query_type` | enum \| null | `null` | `"sql"` or `"querydsl"` — narrows the filter to a specific source kind |
| `filters[].index` | string \| null | `null` | Restricts the filter to a specific index |

#### Identifier conventions

**Send raw identifiers in `field`** — no quoting. The gateway is the single source of truth for SQL dialect handling and will quote per-connector at execute time:

```python
# Right — raw identifier, server quotes per dialect
{"field": "feature_name", "operator": "is", "value": "synopsys_vcs", ...}

# Wrong — pre-quoting is fragile; ties your filter to a specific dialect
{"field": "`feature_name`", ...}     # MySQL-style — only works for MySQL connectors
{"field": "\"feature_name\"", ...}   # double-quoted — only works for non-MySQL dialects
```

The gateway tolerates pre-quoted identifiers (skip-if-quoted is in `quote_ident`) for backward compatibility, but the canonical form is raw. Same convention for any code that builds a `Filter` object from scratch.

### `time_range`

Saved on the visualization and **applied at execute time** as a synthetic `is_between` filter on `source.sql.time_column` (default `@timestamp`). Pass `time_range=` to `execute_visualization` / `execute_dashboard` to override the saved value for a single call — see [Time-range injection](#time-range-injection).

```json
{"kind": "absolute", "from": "2026-04-01T00:00:00Z", "to": "2026-05-01T00:00:00Z"}
{"kind": "relative", "expression": "now-7d"}
```

Only absolute timestamps (ISO-8601 strings or epoch-ms numbers, UTC) are honoured at execute time; the `"relative"` shape is stored but not yet evaluated server-side.

### `render` (escape hatch)

When the typed `chart` + `mapping` + `options` combination can't express what you want, you can bypass the renderer and supply a full ECharts option dict:

| Field | Type | Effect |
|-------|------|--------|
| `render.mode` | enum | `"echarts_injection"` (only mode currently) |
| `render.echarts_option` | object | Full ECharts option dict, merged on top of (or replacing, depending on mode) the auto-generated one |
| `render.column_mapping` | object | Maps your `echarts_option` series fields to data columns so re-execution still binds correctly |

Use sparingly — every override is something `to_echarts_option` no longer manages for you.

## Source kinds

Currently: **`source.kind == "sql"`** with a non-empty `source.sql.raw_query` (raw mode) or `mapping` + `aggregation_type` (Builder mode). The schema also reserves `querydsl` and `promql` slots; those are not yet wired through `execute_visualization`. Runtime filter and time-range overrides are both supported — pass `filters=` and/or `time_range=` to `execute_visualization` / `execute_dashboard` and the gateway AND-merges them into the executed SQL.

## Troubleshooting

**My Y axis is empty.** The fallback picker uses *first non-numeric column → X, first numeric column → Y*. If your SQL returns two non-numeric columns, or both are numeric, set `mapping.x` and `mapping.y` explicitly.

**My chart renders as a table.** `to_echarts_option` falls back to `kind: "table"` when the data doesn't fit the declared chart type (e.g. a pie chart with three numeric columns and no category). Check `visualization_mode` and `mapping`.

**My X axis shows `"10" "11" "2" "3"` in the wrong order.** This shouldn't happen — `to_echarts_option` sorts axis values numeric-aware. If you see it, your X column type is being detected as `string` and the values look numeric but aren't; cast in your SQL (`CAST(hour AS BIGINT)`).

**One panel failed and broke the whole page.** It shouldn't. `execute_dashboard` isolates per-panel errors into `panel["error"]`. If you're seeing a top-level exception, the *dashboard fetch itself* failed (404, auth, network) — that's distinct from per-panel SQL errors.

**My PATCH wiped the `panels` list / `tags` list.** Lists are replaced wholesale by the patch, not merged element-wise. To add an entry, send the full updated list (existing entries + the new one), not just the addition.

**`execute_visualization` returns rows but the chart is blank.** Open the executed payload — `data["columns"]` and `data["rows"]`. If `rows` is non-empty but `columns` doesn't include the columns named in `mapping.x` / `mapping.y`, the SDK's column picker has nothing to point at. Adjust your SQL `AS` aliases or your `mapping`.

**I want to override the time range at execute time.** Pass `time_range={"from": ..., "to": ...}` to `execute_visualization` or `execute_dashboard`. The gateway rewrites it into an `is_between` filter on `source.sql.time_column` (default `@timestamp`). See [Time-range injection](#time-range-injection). Absolute timestamps only — relative syntax like `"now-1h"` is not yet evaluated server-side.

## Examples

- [examples/dashboards/create_and_render.py](../examples/dashboards/create_and_render.py) — Create five real-world chart panels, bundle them into a dashboard, execute every panel in parallel, and render a layout-aware composite HTML page via CSS Grid.
- [examples/dashboards/common/render.py](../examples/dashboards/common/render.py) — Reference HTML renderer using CSS Grid + ECharts. Copy it into your own code.

### Running the dashboard examples

```bash
export INFINO_ACCESS_KEY="your_access_key"
export INFINO_SECRET_KEY="your_secret_key"
export INFINO_ENDPOINT="https://api.infino.ws"
```

The example targets a license-management dataset (`flexlm_cdslmd.rel` + `cdn_product_feature_mapping.rel`). It was chosen because the resulting dashboard exercises a JOIN-based query, a heatmap, a metric card, a horizontal bar, and a pie in one flow — covering more of the renderer than a single-table demo would. Point `INFINO_DEMO_DATASET` / `INFINO_DEMO_MAPPING_DATASET` at your own indices to run against your own data.

```bash
pip install pyecharts                    # optional, only for the HTML render
python -m examples.dashboards.create_and_render
```

See [examples/README.md](../examples/README.md) for the full example index.
