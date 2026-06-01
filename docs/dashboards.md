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
    # Builder-mode aggregating chart:
    #   `mapping.x` — the GROUP BY dimension (categorical / time column).
    #   `mapping.y` — leave EMPTY. The y-axis value is the aggregation
    #     (count / sum / avg) — that's expressed via `aggregation_type`
    #     or `source.sql.metrics[0]`, NOT via mapping.y. Setting
    #     mapping.y on an aggregating chart emits a
    #     `mapping_y_ignored_for_aggregating_chart` warning.
    #   `mapping.series` — optional, splits into one series per
    #     distinct value of this column (stacked bar, multi-line, etc.).
    "mapping": {"x": {"column": "feature_name"}, "y": [], "series": None},
    "aggregation_type": "count",
})
```

The gateway emits SQL equivalent to:

```sql
SELECT feature_name, COUNT(*) as count FROM "license_events"
GROUP BY feature_name ORDER BY feature_name LIMIT 10
```

For connector-backed sources (BigQuery / Snowflake / MySQL / Postgres /
Oracle), set `source.connector_id` (e.g. `"mysql"`, `"bigquery"`) so the
gateway quotes identifiers in the right dialect.

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

### Picking what goes on X and Y

If you're new to visualization, the rule is:

- **X-axis** = the thing you're comparing (the *category* or *dimension*).
  One row per distinct value of this column. Goes on the horizontal axis
  for bar / line / area / scatter, becomes the slice label for pie, and
  the first axis for heatmap.
- **Y-axis** = the *measurement* — the number you compute for each row.
  Usually an aggregation: `COUNT(*)`, `SUM(amount)`, `AVG(latency)`. Goes
  on the vertical axis.

A quick way to sanity-check: read the chart's title aloud as
*"Y-name **by** X-name"*. If that sentence makes sense, the axes are
right.

| Chart you want | X (the thing) | Y (the measurement) |
|---|---|---|
| Bar / horizontalBar — "denials per feature" | `feature_name` | `COUNT(*)` |
| Line / area — "denials per day" | `@timestamp` (with `bucket: "day"`) | `COUNT(*)` |
| Pie — "denials by stage (share of total)" | `stage` | `COUNT(*)` |
| Heatmap — "denials by feature × hour-of-day" | `hour_of_day` (or `@timestamp` with `bucket: "hour"`) | `COUNT(*)`, with `mapping.series` = `feature_name` |
| Metric / gauge — single KPI like "total denials" | (none) | `COUNT(*)` |
| Scatter — "latency vs. payload size" | numeric column (`payload_size`) | numeric column (`latency_ms`) — no aggregation |
| Table — "recent denials, last 100 rows" | (none) | the columns you want to project |

In Infino's spec:
- The X column → `mapping.x.column`
- The aggregation function and (if needed) the column it operates on
  → `aggregation_type` shorthand OR `source.sql.metrics[0]`
- A second categorical breakdown (multi-series, heatmap's second axis)
  → `mapping.series`

You **don't** set the Y-axis column directly for aggregating charts —
the aggregation (`COUNT(*)`, `SUM(col)`, etc.) IS the Y-axis value, and
the gateway derives the response column name from it. The only chart
types where `mapping.y` carries a raw column reference are `scatter`
(uses `y[0]` as a numeric column with no aggregation) and `table` (uses
the whole list as the SELECT column list).

### Where does the metric column come from?

Two ways to express the y-axis aggregation. Both are accepted; pick by what
the chart needs.

**`aggregation_type` shorthand** — for the simple case. Set the function
name, the gateway picks the column automatically:

- `aggregation_type: "count"` → emits `COUNT(*) as count`. No column
  needed; the UI doesn't ask for one either.
- `aggregation_type: "sum"` / `"avg"` → the gateway also looks at
  `mapping.y[0]` for the column-to-aggregate (this is the one place
  Builder mode reads from `mapping.y`, and only as a fallback when
  `metrics[]` is empty). For new code, prefer the explicit form below
  instead — it's clearer and works with ordering.

**Explicit `source.sql.metrics[0]`** — for everything else (top-N
ordering, multi-metric in the future, when you want to reference the
metric by id elsewhere in the spec). Set `id`, `function`, and `column`:

```python
"source": {
    "kind": "sql",
    "index": "orders.rel",
    "sql": {
        "metrics": [
            {"id": "rev", "function": "sum", "column": "revenue"}
        ],
        "limit": 10,
    },
},
"chart": {"type": "bar"},
"mapping": {"x": {"column": "customer_name"}, "y": [], "series": None},
# No `aggregation_type` — metrics[0] is authoritative.
```

When you need to reference the metric in `order_by`, use `metric_id`
— it's rename-safe and you don't need to know the alias the gateway
will generate (see [Top-N pattern](#top-n-pattern) below).

**Don't set both.** If `source.sql.metrics[0]` is populated, it wins;
`aggregation_type` is ignored. The gateway doesn't warn (both fields are
legitimate inputs) but the agent-experience is clearer if you pick one.

**Don't put the metric column in `mapping.y`.** For aggregating charts
(`bar` / `horizontalBar` / `line` / `area` / `pie` / `heatmap` /
`metric` / `gauge`), `mapping.y` is ignored at SQL-emission time and
the gateway emits a `mapping_y_ignored_for_aggregating_chart` warning.
The two exceptions are `scatter` (where `y[0]` is the raw y-axis
column with no aggregation) and `table` (where `mapping.y` is the
SELECT column list).

### Multi-series — splitting one chart into N series

Set `mapping.series` to a categorical column. The renderer pivots the
result into one series per distinct value (stacked bar, multi-line,
heatmap second axis):

```python
viz = sdk.create_visualization({
    "title": "Denials per feature, split by region",
    "source": {
        "kind": "sql",
        "index": "license_events",
        "sql": {
            "metrics": [{"id": "m1", "function": "count", "column": None}],
            "limit": 50,
        },
    },
    "chart": {"type": "bar"},
    "mapping": {
        "x": {"column": "feature_name"},
        "series": "region",            # ← one bar series per region
        "y": [],
    },
})
```

`mapping.series` is **required for `heatmap`** (the renderer needs the
second categorical axis and can't infer it). It's **ignored** for
`pie` / `scatter` / `metric` / `gauge` / `table`. For bar / line /
area, it's optional.

### Time bucketing — `mapping.x.bucket`

For time-series charts, set `mapping.x.bucket` to a granularity name
and the gateway handles the dialect-specific truncation for you (no
`DATE_TRUNC` / `TIMESTAMP_TRUNC` / `DATE_FORMAT` to remember per engine):

```python
viz = sdk.create_visualization({
    "title": "Denials by day",
    "source": {
        "kind": "sql",
        "index": "license_events",
        "sql": {"limit": 1000},
    },
    "chart": {"type": "line"},
    "mapping": {
        "x": {"column": "@timestamp", "bucket": "day"},  # bucket nested in x
        "y": [],
    },
    "aggregation_type": "count",
})
```

Accepted granularities: `minute`, `hour`, `day`, `week`, `month`,
`quarter`, `year`. Week is ISO-8601 Monday-start across all engines.
The response column name stays stable as `mapping.x.column` regardless
of which engine produced the data — renderers bind to `binding.x`
directly without case-or-quoting drift.

Oracle returns a 400 with a hint to bake the truncation into
`raw_query` (per-engine Oracle support is on the roadmap).

`mapping.x.bucket` is mutually exclusive with `mapping.top` +
`mapping.other_bucket` (the `'Other'` string literal can't share a
column with a date-typed expression — the gateway emits
`top_n_other_bucket_incompatible_with_bucket` and skips the rollup).

### Top-N pattern

The classic "top 10 customers by GMV" pattern uses `source.sql.order_by`
to override the default `ORDER BY <x-axis>`. Three shapes are accepted;
**use `metric_id`** — it's rename-safe and the gateway resolves it to the
right alias without you needing to know the alias formula.

```python
# Preferred — order by metric_id (rename-safe)
viz = sdk.create_visualization({
    "source": {
        "kind": "sql",
        "index": "Customer_PnL_v2",
        "connector_id": "bigquery",
        "sql": {
            "metrics": [{"id": "gmv", "function": "sum", "column": "Cust_SKU_GMV"}],
            "order_by": [{"metric_id": "gmv", "direction": "desc"}],
            "limit": 10,
        },
    },
    "chart": {"type": "bar"},
    "mapping": {"x": {"column": "Customer_Name"}, "y": [], "series": None},
})
```

The chart renders the top 10 customers sorted by `SUM(Cust_SKU_GMV)`
descending. `metric_id: "gmv"` references `metrics[0].id`; rename the
column underneath and the order_by entry follows automatically.

Unresolved `metric_id` emits `order_by_metric_id_unresolved` in
`metadata.warnings[]` and the entry is dropped (the SQL still runs;
ORDER BY falls back to the chart default).

Direction defaults to `asc`; invalid values clamp to `asc` (caller typos
won't propagate as SQL). Multiple entries are supported and preserved in
spec order:

```python
"order_by": [
    {"column": "region", "direction": "asc"},
    {"metric_id": "revenue", "direction": "desc"},
],
```

For dimensions that aren't aggregated (scatter plots, raw row mode),
reference real schema columns by name:

```python
"order_by": [{"column": "@timestamp", "direction": "desc"}],
```

#### `order_by[]` alternate shapes

**Explicit aggregate** — pass the raw column plus a `function`. Readable
without knowing the alias formula:

```python
"order_by": [
    {"column": "revenue", "function": "sum", "direction": "desc"},
],
```

Recognised functions: `count` / `sum` / `avg` / `min` / `max`. Unknown
function names emit `order_by_function_unknown` and fall back to
ordering by the bare column.

**Legacy / by alias** — reference the generator-derived alias name
directly. Works but you have to know the formula:

| Aggregation | Alias |
|-------------|-------|
| `count` (or no Y-axis) | `count` |
| `sum` on column `revenue` | `sum_revenue` |
| `avg` on column `latency_ms` | `avg_latency_ms` |

```python
"order_by": [{"column": "sum_revenue", "direction": "desc"}],
```

The metric alias name leaks an implementation detail; prefer `metric_id`
or `{column, function}` for new code.

### Top-N + Other rollup

For high-cardinality dimensions (25 lanes, 200 SKUs, 1k customers) plain
top-N drops the long tail entirely. Set `mapping.top: N` +
`mapping.other_bucket: true` and the gateway emits a CASE-rewrite that
aggregates every non-top value into a literal `'Other'` bucket:

```python
viz = sdk.create_visualization({
    "title": "Lanes by GMV (top 5 + Other)",
    "source": {
        "kind": "sql",
        "index": "Customer_PnL_v2",
        "connector_id": "bigquery",
        "sql": {
            "metrics": [{"id": "m1", "function": "sum", "column": "Cust_SKU_GMV"}],
            "order_by": [{"metric_id": "m1", "direction": "desc"}],
        },
    },
    "chart": {"type": "pie"},
    "mapping": {
        "x": {"column": "Lane"},
        "top": 5,
        "other_bucket": True,
    },
})
# Gateway emits:
#   SELECT
#     CASE WHEN `Lane` IN (
#       SELECT `Lane` FROM `Customer_PnL_v2`
#       GROUP BY `Lane` ORDER BY SUM(`Cust_SKU_GMV`) DESC LIMIT 5
#     ) THEN `Lane` ELSE 'Other' END AS `Lane`,
#     SUM(`Cust_SKU_GMV`) AS `sum_Cust_SKU_GMV`
#   FROM `Customer_PnL_v2`
#   GROUP BY 1
#   ORDER BY `sum_Cust_SKU_GMV` DESC
```

Rules:

- The rollup applies to `mapping.x`.
- `top` without `other_bucket: true` is the same as vanilla top-N from
  `sql.order_by + sql.limit`; the gateway emits
  `top_n_without_other_bucket_use_limit` and doesn't rewrite the SQL.
- Mutually exclusive with `mapping.x.bucket` — the 'Other' string literal
  can't share a column with a date-typed expression. Emits
  `top_n_other_bucket_incompatible_with_bucket`; the rollup is skipped
  and bucketing wins.
- `sql.limit` still bounds the final row count — set it to `N + 1` if
  you want exactly the top-N plus the 'Other' row.

### Builder mode by chart type

What goes where, per chart type. Required fields in **bold**:

| `chart.type` | `mapping.x` | metric / value | `mapping.series` | `mapping.y` |
|---|---|---|---|---|
| `bar`, `horizontalBar`, `line`, `area` | **the GROUP BY column** | `aggregation_type` or `metrics[0]` | optional — splits into multi-series | leave empty |
| `pie` | **slice category** | `aggregation_type` or `metrics[0]` | ignored | leave empty |
| `heatmap` | **first dimension** (often time) | `aggregation_type` or `metrics[0]` (the cell value) | **second dimension** | leave empty |
| `metric`, `gauge` | leave empty / null | `aggregation_type` or `metrics[0]` | ignored | leave empty |
| `scatter` | **x column** (numeric, no aggregation) | n/a — set `aggregation_type: "none"` | optional label column | **y[0]** is the y column |
| `table` | leave empty / null | n/a | ignored | columns to SELECT (empty → SELECT \*) |

Rules of thumb:
- Aggregating charts (`bar` / `line` / `area` / `pie` / `heatmap` /
  `metric` / `gauge`) read the y from `metrics[0]` or `aggregation_type`.
  `mapping.y` is preserved on the stored config but **ignored** for
  SQL emission — the gateway warns
  (`mapping_y_ignored_for_aggregating_chart`) if you set it.
- `scatter` and `table` are the only chart types where `mapping.y`
  drives SQL. Scatter takes `y[0]`; table takes the whole array.

### Common pitfalls in Builder mode

Each one corresponds to a gateway warning in `metadata.warnings[]` — if
you see the code, the fix is one of these:

| Symptom / warning code | What happened | Fix |
|---|---|---|
| `missing_x_axis_for_chart` | Chart type needs an X dimension but `mapping.x` is null. Gateway falls back to `SELECT *` and the chart can't bind. | Set `mapping.x = {"column": "..."}`. |
| `missing_series_for_heatmap` | Heatmap requires a second categorical axis. | Set `mapping.series = "<column>"`. |
| `mapping_y_ignored_for_aggregating_chart` | You put the metric column in `mapping.y` instead of `metrics[0].column`. The SQL emits `COUNT(*)` (the fallback) instead of your intended aggregation. | Move the column to `metrics[0]` with the function you want. |
| `unknown_aggregation_function` | `metrics[0].function` isn't one of `count` / `sum` / `avg` / `min` / `max` / `none`. Gateway falls back to `count`. | Use one of the allowlisted functions. |
| `multi_metric_truncated` | `metrics[]` has more than one entry; only `metrics[0]` is honoured today. | Drop the extras or split into separate vizzes. |
| `metric_column_unused_with_count_aggregation` | `metrics[0].column` is set but `function` is `count`. The column is dead — `COUNT(*)` doesn't reference it. | Change `function` to `sum` / `avg` to aggregate the column, or remove the column field. |
| `order_by_column_unrecognized` | `order_by[].column` doesn't match `mapping.x`, `mapping.series`, or any metric alias the gateway will emit. CoreDB silently drops bad refs. | Either reference a real column / metric alias, or use `metric_id` for rename-safe ordering. |
| `order_by_metric_id_unresolved` | `order_by[].metric_id` doesn't match any `metrics[].id`. | Fix the id, or use `column` / `function` shape instead. |
| `high_cardinality_no_top_n` | Pie / bar / horizontalBar returned > 15 rows with no Top-N rollup. The chart is unreadable. | Set `mapping.top: N` + `mapping.other_bucket: true`. |
| `top_n_without_other_bucket_use_limit` | `mapping.top` is set but `mapping.other_bucket` isn't `true`. Without Other-rollup, this is the same as `sql.limit + sql.order_by`. | Add `"other_bucket": True` to keep the long tail, or just use `sql.limit`. |
| `top_n_other_bucket_incompatible_with_bucket` | Top-N + Other rollup AND `mapping.x.bucket` are mutually exclusive (the 'Other' string literal can't share a column with a date type). | Pick one. Bucketing wins; the rollup is skipped. |

Warnings are advisory — the query still runs, just maybe not the way
you wanted. Always inspect `metadata.warnings[]` on the execute
response when iterating on a Builder-mode viz.

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
  - `metadata.binding` — `{x, y[], series, value}` — the gateway's axis→column contract. **Renderers should read this** instead of poking at the saved viz spec to figure out which column is the y axis. See [Response contract — metadata.binding](#response-contract--metadatabinding) for the full shape, per-chart-type expectations, and consumer pattern.
  - `metadata.filters_applied` / `metadata.filters_skipped` surface which filters made it into the dispatched SQL vs. which the rewriter couldn't safely inject (parser edge cases, etc.). Unrecognised filters never fail the call — the original SQL still runs.
  - `metadata.warnings` is a list of `{code, message}` advisories for silent-fail Builder configs the gateway accepted but that produce surprising results — typo'd `connector_id`, missing axes, `raw_query` colliding with Builder fields. See [Builder-mode warnings](#builder-mode-warnings).
- **`to_echarts_option(viz, data)`** — Pure function (no network call). Reads `data.metadata.binding` for all axis-to-column mapping; consults the viz spec only for `chart.type`, title, and presentational options (formatting, legend). Returns one of three render-ready shapes depending on what makes sense for the data:
  - **`kind == "echarts"`** — `result["option"]` is plain ECharts JSON. Pass it straight to `echarts.setOption(...)` in the browser, or to pyecharts in Python. Covers `bar`, `horizontalBar`, `line`, `area`, `pie`, `heatmap`, `scatter`.
  - **`kind == "table"`** — `result["columns"]` and `result["rows"]` for inline HTML / pandas rendering. Returned when `chart.type == "table"` or when the data doesn't fit the declared chart type.
  - **`kind == "metric"`** — `result["value"]` is the single aggregated number with optional `result["formatting"]` (`prefix`, `suffix`, `decimals`, `abbreviate`, `thousands_separator`). Returned when `chart.type == "metric" | "gauge"`.

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
    "mapping": {"x": null, "y": [], "series": null},
    "options": {"metric_formatting": null},
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
    {"name": "sum_denials", "type": "number"}
  ],
  "rows": [
    {"feature": "synopsys_vcs", "sum_denials": 1284},
    {"feature": "cadence_innovus", "sum_denials": 902}
  ],
  "metadata": {
    "source_kind": "sql",
    "row_count": 2,
    "truncated": false,
    "took_ms": 47,
    "executed_query": "SELECT \"feature\", SUM(\"denials\") AS \"sum_denials\" FROM ... GROUP BY \"feature\"",
    "filters_applied": [],
    "filters_skipped": [],
    "warnings": [],
    "binding": {
      "x": "feature",
      "y": ["sum_denials"],
      "series": null,
      "value": null
    }
  }
}
```

Column `type` is normalised to `string` / `number` / `boolean` / `date` / `null`.

### Response contract — `metadata.binding`

Every successful execute response carries `metadata.binding`. This is the single source of truth a renderer should consult to map chart axes to response columns. **Do not read the saved viz spec (`mapping.x`, `mapping.y`, `metrics[].column`) to resolve columns** — those describe the caller's intent, not the response. The gateway computes the binding from the spec + chart type and publishes it on the response so every consumer (Python SDK, MCP, any future BI tool) sees the same contract.

```typescript
interface ResponseBinding {
  x: string | null;              // categorical x-axis column
  y: string[];                   // value column(s) — metric aliases for builder mode
  series: string | null; // pivot / heatmap second axis
  value: string | null;          // single-value column for `metric` / `gauge`
}
```

#### Why the binding exists

In builder mode the gateway emits a SQL alias for each metric: `SUM("denials") AS "sum_denials"`. The response column carrying the value is `sum_denials`, **not** the input column `denials` you set in `mapping.y`. A renderer that naively does `row[mapping.y[0]]` gets `undefined` and draws blank bars. The binding eliminates this whole class of bug — `binding.y[0]` is always a real response column name.

#### Per-chart-type shape

| `chart.type` | `binding.x` | `binding.y` | `binding.series` | `binding.value` |
|---|---|---|---|---|
| `bar` / `horizontalBar` / `line` / `area` | x column | `["<metric_alias>"]` (e.g. `["sum_denials"]`) | pivot column (when multi-series) | `null` |
| `pie` | category column | `["<metric_alias>"]` | `null` | `null` |
| `heatmap` | first axis column | `["<metric_alias>"]` (cell value) | second axis column | `null` |
| `scatter` | x column (raw) | `[<y_column>]` (raw) | `null` | `null` |
| `metric` / `gauge` | `null` | `[]` | `null` | `"<metric_alias>"` |
| `table` | `null` | `[]` | `null` | `null` |

#### Consumer pattern (Python)

```python
data = sdk.execute_visualization(viz_id)
binding = data["metadata"]["binding"]

# Bar / line / area / pie:
x_vals = [r[binding["x"]] for r in data["rows"]]
y_vals = [r[binding["y"][0]] for r in data["rows"]]

# Metric / gauge:
single = data["rows"][0][binding["value"]] if data["rows"] else None

# Multi-series pivot (line / bar with series):
split = binding["series"]
if split:
    by_series = {}
    for r in data["rows"]:
        by_series.setdefault(r[split], []).append((r[binding["x"]], r[binding["y"][0]]))
```

`InfinoSDK.to_echarts_option(viz, data)` does exactly this internally — pass the response and a stored viz; you get back ECharts JSON without ever touching the spec's `mapping` for column resolution.

#### Raw query mode

When you set `source.sql.raw_query` (custom SQL), the gateway can't know which response columns are categorical vs metric — there's no `metrics[]` to derive aliases from. Two options:

- **Hint via `mapping.x` / `mapping.series`** in the saved viz spec. The gateway propagates these into `binding`.
- **Let the gateway infer.** If `mapping` is empty, the gateway picks `binding.x` = first non-numeric response column, `binding.y[0]` = first numeric column (skipping anything already bound to `x` or `series`).

Both paths produce the same `binding` envelope, so the renderer doesn't care which one the caller used.

#### Forward compatibility

`metadata.binding` is source-kind-agnostic. When QueryDSL or PromQL builder modes ship, the gateway will populate the same shape from their specs. **Renderers written against `binding` keep working unchanged.** Renderers that walk the spec break the day a new source kind lands.

### Builder-mode warnings

`metadata.warnings` is a list of `{code, message}` advisories the gateway emits for Builder-mode configs that it accepted but that produce silent-fail results (empty chart, wrong dialect quoting, dropped fields):

| Code | Trigger |
|------|---------|
| `missing_x_axis_for_chart` | A non-table `chart.type` (other than `metric` / `gauge`) is set but `mapping.x` is empty. Gateway falls back to `SELECT *`; chart can't bind. |
| `missing_series_for_heatmap` | `chart.type` is `heatmap` but `mapping.series` is empty. Heatmap renderer needs two dimensions. |
| `metric_column_unused_with_count_aggregation` | `source.sql.metrics[0].column` is set but `function` is `count` — the column is unused (gateway always emits `COUNT(*)`). Set `function` to `sum` / `avg` to aggregate the column. |
| `mapping_y_ignored_for_aggregating_chart` | `mapping.y` is set on a chart type that derives the y axis from `metrics[]` (bar / line / area / pie / heatmap / metric / gauge). The field is ignored; drop it from the payload. |
| `raw_query_overrides_builder_fields` | Caller set `source.sql.raw_query` AND fields that only affect Builder-mode SQL emission (`source.sql.metrics`, `source.sql.order_by`, `mapping.x.bucket`, `mapping.top`, `mapping.other_bucket`). Raw query wins for SQL; the listed fields are dropped. `mapping.x` / `mapping.y` / `mapping.series` are NOT included — they're still used to derive `metadata.binding` so the renderer can resolve chart axes against the raw_query's response columns. |
| `unknown_connector_id` | `source.connector_id` is a string but not in `{mysql, bigquery, snowflake, oracle_db}`. Gateway falls back to the default SQL dialect — emitted identifier quoting may be wrong for the target engine. |
| `order_by_function_unknown` | `order_by[].function` is not one of `count` / `sum` / `avg` / `min` / `max`. Entry falls back to ordering by the bare column. |
| `order_by_metric_id_unresolved` | `order_by[].metric_id` doesn't match any `sql.metrics[].id`. Entry is skipped; ORDER BY falls back to the chart default. |
| `x_bucket_conflicts_with_date_interval` | `mapping.x.bucket` and `sql.dimensions[].date_interval` (on the X column) disagree. `mapping.x.bucket` wins. |
| `dimension_date_interval_ignored` | `sql.dimensions[].date_interval` set on a dimension that doesn't match `mapping.x`. Only the X dimension is bucketed. |
| `dimension_custom_expression_ignored` | `sql.dimensions[].custom_expression` is set; builder mode doesn't honour SQL fragments — switch to `raw_query` mode. |
| `top_n_other_bucket_unsupported_on_non_x` | `top` / `other_bucket` set on a dimension that doesn't match `mapping.x`. Only the X axis is rewritten with the CASE rollup. |
| `top_n_without_other_bucket_use_limit` | `top` set without `other_bucket: true`. Vanilla top-N is the same as `sql.limit + sql.order_by`; use those instead. |
| `top_n_other_bucket_incompatible_with_bucket` | `top` + `other_bucket: true` AND `mapping.x.bucket` are mutually exclusive — the 'Other' string literal can't share a column with a date type. Drop one. |
| `top_n_zero_ignored` | `top: 0` is meaningless; rollup skipped. |
| `unknown_aggregation_function` | `sql.metrics[0].function` is not one of `count` / `sum` / `avg` / `min` / `max` / `none`. Gateway falls back to `count`. Previously any string was uppercased into a SQL function name (silent data corruption). |
| `multi_metric_truncated` | `sql.metrics[]` has more than one entry; only `metrics[0]` is honoured. Multi-metric SQL emission isn't supported yet — drop the extras or split into separate visualisations. |
| `multi_y_truncated` | Scatter chart with more than one `mapping.y` entry. Scatter only honours `y[0]`; drop the extras or switch to another chart type. (Aggregating charts ignore `mapping.y` entirely — see `mapping_y_ignored_for_aggregating_chart` instead.) |
| `order_by_column_unrecognized` | `order_by[].column` doesn't match `mapping.x`, `mapping.series`, or any metric alias. CoreDB silently drops bad refs; this surfaces them. |
| `high_cardinality_no_top_n` | pie / bar / horizontalBar returned more than 15 rows with no `mapping.top` set. The chart is likely unreadable; consider `mapping.top: N` + `mapping.other_bucket: true` for an 'Other' rollup. |

Codes are machine-stable; messages are human-readable and may evolve. Suggested handling:

```python
data = sdk.execute_visualization(viz_id)
for w in data.get("metadata", {}).get("warnings", []):
    logger.warning("viz %s: %s — %s", viz_id, w["code"], w["message"])
```

Warnings never fail the call — the query runs and rows come back. They're advisory only.

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
| `table` | `table` | Raw `{columns, rows}` for HTML / pandas (set `chart.type: "table"` — The legacy `visualization_mode` field is retired; `chart.type` is the single render-kind discriminator) |

**Picking columns.** `to_echarts_option` uses `viz.mapping.x`, `viz.mapping.y`, and `viz.mapping.series` to decide which columns become which axes. If `mapping` is empty it falls back to "first non-numeric column → X, first numeric column → Y" — so you can omit `mapping` for simple bar / line charts.

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
| `chart.type` | enum | (required) | `bar`, `horizontalBar`, `line`, `area`, `scatter`, `pie`, `heatmap`, `metric`, `gauge`, `table`. The legacy `visualization_mode` field is retired; `chart.type` is the single render-kind discriminator. Use `"table"` for raw-rows display, `"metric"` / `"gauge"` for single-value display. |
| `mapping` | object | `{x: null, y: [], series: null}` | See [`mapping.*`](#mapping-fields). **In Builder mode, drives SQL generation.** |
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
| `source.sql.dimensions` | array | `[]` | **Deprecated** (tranche 3). Chart-level concepts that used to live here — `top` / `other_bucket` / `date_interval` — moved to `mapping.top` / `mapping.other_bucket` / `mapping.x.bucket`. Gateway migrates legacy payloads on read. New payloads should omit the field or send `[]`. |
| `source.sql.metrics` | array | `[]` | Builder-mode aggregation spec. Each entry: `{id, function, column, alias?, custom_expression?}`. `function` is one of `count` / `sum` / `avg` / `none`. The gateway reads `metrics[0]` to pick the aggregation; when omitted, defaults to `COUNT(*) as count`. |
| `source.sql.order_by` | array | `[]` | Builder-mode ORDER BY spec. Each entry: `{column, direction}` with `direction ∈ {asc, desc}`. `column` may be a real schema column OR an aggregation alias the gateway generates (`count`, `sum_<col>`, `avg_<col>`). Falls back to `ORDER BY <x-axis>` when omitted. See [Top-N pattern](#top-n-pattern). |

### `mapping.*` fields

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `mapping.x` | `{column, bucket?}` \| string \| null | `null` | The X-axis dimension. Canonical wire shape is the **object form** `{column: "ts", bucket?: "month"}`. Bare-string form `"x": "ts"` is accepted on input and migrated to the object form on read. Falls back to "first non-numeric column" when `null`. **Optional for `chart.type` `metric` / `gauge`** — gateway emits `SELECT <agg> FROM <table>` and ignores the axis. |
| `mapping.y` | string[] | `[]` | Raw response-column reference(s). Semantics depend on `chart.type`: <ul><li>`scatter` — `y[0]` is the y-axis column (no aggregation).</li><li>`table` — list of columns to SELECT (empty → `SELECT *`).</li><li>`bar` / `line` / `area` / `pie` / `heatmap` / `metric` / `gauge` — **ignored**. The y axis comes from `source.sql.metrics[]` for these chart types; setting `mapping.y` triggers a `mapping_y_ignored_for_aggregating_chart` warning.</li></ul> |
| `mapping.series` | string \| null | `null` | Splits data by a second categorical column. **Semantics depend on `chart.type`** — see table below. **Required for `heatmap`**; ignored for `pie` / `scatter` / `metric` / `gauge` / `table`. Renamed from `series_split_by` to align with industry vocabulary (Evidence, ECharts, Superset). The old name is accepted on input for back-compat. |
| `mapping.x.bucket` | string \| null | `null` | Time-truncation granularity nested inside `mapping.x`. One of `minute` / `hour` / `day` / `week` / `month` / `quarter` / `year`. Gateway emits dialect-specific truncation: `DATE_TRUNC` (ANSI / CoreDB / Postgres / Snowflake), `TIMESTAMP_TRUNC` (BigQuery), per-granularity `DATE_FORMAT` / `DATE` / `MAKEDATE` (MySQL). Oracle returns a 400 — bake the truncation into `raw_query` for now. The legacy sibling form `mapping.x_bucket` is accepted on input and folded into `mapping.x.bucket` on read. |
| `mapping.top` | integer \| null | `null` | Top-N filter on `mapping.x`. Pair with `other_bucket: true` to roll non-top values into an `'Other'` bucket. Mutually exclusive with `mapping.x.bucket`. Without `other_bucket: true`, equivalent to `sql.limit + sql.order_by` (and the gateway warns). See [Top-N + Other rollup](#top-n--other-rollup). |
| `mapping.other_bucket` | boolean \| null | `null` | Include a literal `'Other'` rollup row catching everything outside the top-N. Only meaningful when `mapping.top` is also set. |

#### `series` semantics per chart type

The field's role depends on `chart.type`. One column reference, three behaviours:

| `chart.type` | What `series` does | Required? |
|---|---|---|
| `bar` / `horizontalBar` / `line` / `area` | Pivot column for stacking / multi-series (one series per distinct value) | optional |
| `heatmap` | **Second categorical axis** (the y-axis category) | **required** — heatmap renderer can't infer it |
| `pie` / `scatter` / `metric` / `gauge` / `table` | Ignored | n/a |

If you need stacked bars AND a heatmap-style second axis, those are two different vizzes — `series` only carries one column at a time.

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
| `filters[].id` | string | auto-stamped server-side | Stable id for this filter. The server auto-stamps a uuid hex when omitted; only matters if you need to reference the same filter across update calls. Filter dedupe is keyed by `field`, not `id`. |
| `filters[].field` | string | (required) | Column or field name — **raw, no quoting** (see note below) |
| `filters[].operator` | enum | (required) | `is`, `is_not`, `is_one_of`, `is_not_one_of`, `is_between`, `is_not_between`, `exists`, `does_not_exist`, `contains` |
| `filters[].value` | any | `null` for `exists` / `does_not_exist`; required otherwise | Operand value; shape depends on the operator (`is_between` takes `[lo, hi]` or `{from, to}`; `contains` takes a scalar substring — `%` and `_` are escaped server-side so the value matches literally). `exists` and `does_not_exist` ignore the value — you can omit it. |
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

**My chart renders as a table.** `to_echarts_option` falls back to `kind: "table"` when the data doesn't fit the declared chart type (e.g. a pie chart with three numeric columns and no category). Check `chart.type` and `mapping`.

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
