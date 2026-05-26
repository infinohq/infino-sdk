# AGENTS.md — Infino visualizations & dashboards

Compact rules for AI coding agents (Claude Code, Cursor, aider, Cline, Codex, OpenHands) building visualizations or dashboards with the Infino Python SDK.

Read this first. For long-form prose, see [`docs/dashboards.md`](../../docs/dashboards.md). For a runnable end-to-end example, see [`create_and_render.py`](create_and_render.py) in this folder.

## Mental model

- A **visualization** = a SQL query + a chart type. Saved server-side, addressable by id.
- A **dashboard** = an ordered list of panels. Each panel references one saved visualization by `viz_id`.
- The SDK is renderer-agnostic. `execute_*` returns `{columns, rows, metadata}`; `to_echarts_option(viz, data)` turns those into an ECharts option you can render with any frontend (or pyecharts in Python).
- Lifecycle: `create_visualization` → `execute_visualization` → `to_echarts_option` → render. For dashboards, replace the middle step with `execute_dashboard` (parallel fan-out).

## Task → SDK call

| User intent | Call this |
|-------------|-----------|
| "Save a chart showing X" | `sdk.create_visualization(spec)` |
| "Show me a chart of X" (one-off) | `create_visualization` then `execute_visualization` then `to_echarts_option` |
| "Update the title / SQL / limit on chart Y" | `sdk.update_visualization(viz_id, partial)` |
| "Delete chart Y" | `sdk.delete_visualization(viz_id)` |
| "List all my charts" | `sdk.list_visualizations(limit=, offset=)` |
| "Make a dashboard with these charts" | `sdk.create_dashboard({"title", "panels": [{"viz_id": ...}]})` |
| "Render the whole dashboard" | `sdk.execute_dashboard(dashboard_id)` — **not** a loop of `execute_visualization` |
| "Add one panel to dashboard D" | Fetch with `get_dashboard`, append to `panels`, send full list back via `update_dashboard` |
| "Show a single number (total / count)" | `chart.type: "metric"` + `visualization_mode: "table"` |
| "Show raw rows in a table" | `visualization_mode: "table"` |

## Chart skeletons

Use the smallest viable body. The server fills `mapping`, `options`, `tags`, etc. when omitted.

### Bar / horizontal bar / line / area / scatter

```python
sdk.create_visualization({
    "title": "Top denials by feature",
    "source": {
        "kind": "sql",
        "index": "license_events",
        "sql": {"raw_query": "SELECT feature, COUNT(*) AS denials FROM license_events WHERE event_type='DENIED' GROUP BY feature ORDER BY denials DESC LIMIT 10"},
    },
    "chart": {"type": "bar"},   # or "horizontalBar" / "line" / "area" / "scatter"
})
```

Two columns. First non-numeric → X axis. First numeric → Y axis.

### Pie

```python
sdk.create_visualization({
    "title": "Denials by stage",
    "source": {
        "kind": "sql",
        "index": "license_events",
        "sql": {"raw_query": "SELECT stage, COUNT(*) AS denials FROM license_events WHERE event_type='DENIED' GROUP BY stage"},
    },
    "chart": {"type": "pie"},
})
```

Two columns: category + value.

### Heatmap (3-column with explicit mapping)

```python
sdk.create_visualization({
    "title": "Denials by feature x hour",
    "source": {
        "kind": "sql",
        "index": "license_events",
        "sql": {"raw_query": "SELECT EXTRACT(HOUR FROM `@timestamp`) AS hour, feature, COUNT(*) AS denials FROM license_events WHERE event_type='DENIED' GROUP BY EXTRACT(HOUR FROM `@timestamp`), feature LIMIT 200"},
    },
    "chart": {"type": "heatmap"},
    "mapping": {"x": "hour", "y": ["denials"], "series_split_by": "feature"},  # REQUIRED for heatmap
})
```

Heatmaps need three columns and `mapping.series_split_by` set — the fallback picker can't infer it.

### Metric (single number KPI)

```python
sdk.create_visualization({
    "title": "Total denials",
    "source": {
        "kind": "sql",
        "index": "license_events",
        "sql": {"raw_query": "SELECT COUNT(*) AS denials FROM license_events WHERE event_type='DENIED'"},
    },
    "chart": {"type": "metric"},
    "visualization_mode": "table",   # REQUIRED for metric — pulls the scalar from the row
    "options": {
        "metric_formatting": {"thousands_separator": ",", "decimals": 0},
    },
})
```

Optional formatting fields: `prefix`, `suffix`, `decimals`, `abbreviate`, `thousands_separator`.

### Table (raw rows)

```python
sdk.create_visualization({
    "title": "Recent denials",
    "source": {
        "kind": "sql",
        "index": "license_events",
        "sql": {"raw_query": "SELECT `@timestamp`, feature, user_name FROM license_events WHERE event_type='DENIED' ORDER BY `@timestamp` DESC LIMIT 100"},
    },
    "chart": {"type": "bar"},          # ignored when mode == "table"
    "visualization_mode": "table",
})
```

## Dashboard skeleton

```python
dash = sdk.create_dashboard({
    "title": "License Overview",
    "panels": [
        {"viz_id": viz_1, "layout": {"x": 0,  "y": 0,  "w": 12, "h": 8}},   # metric card
        {"viz_id": viz_2, "layout": {"x": 12, "y": 0,  "w": 18, "h": 16}},  # main chart
        {"viz_id": viz_3, "layout": {"x": 30, "y": 0,  "w": 18, "h": 16}},  # secondary chart
    ],
})

panels = sdk.execute_dashboard(dash["id"])   # parallel fan-out, one call
for p in panels:
    if p["error"]:
        # render an error placeholder at p["layout"]; do not skip silently
        continue
    spec = sdk.to_echarts_option(p["viz"], p["data"])
    # render `spec` at `p["layout"]`
```

**Layout grid is 48 columns wide.** Sizing reference:

| Purpose | `w × h` |
|---------|---------|
| Metric card | `12 × 8` |
| Quarter-width chart | `12 × 16` |
| Third-width chart | `16 × 16` |
| Half-width chart | `24 × 16` |
| Full-width chart | `48 × 16` |

Omit `layout` on every panel and the server auto-flows into a 2-column grid.

## Decision rules

- **Mapping**: omit `mapping` if SQL returns exactly two columns (one non-numeric for X, one numeric for Y). Set it explicitly for heatmap, multi-series line, or when SQL has multiple numeric columns and you need to pick.
- **`visualization_mode`**:
  - `"table"` for raw row listings (regardless of `chart.type`)
  - `"table"` is also required when `chart.type == "metric"` (the metric pulls a scalar from row 0)
  - `"chart"` (default) for normal charts
- **Single-number KPI**: always `chart.type: "metric"` + `visualization_mode: "table"`. SQL must return one row with one numeric column.
- **Bar vs. horizontalBar**: use `horizontalBar` when category labels are long (feature names, full paths, etc.) so they stay readable.
- **`LIMIT`**: put it in `raw_query`. The server-default `source.sql.limit` is a cap, not a hint; it's ignored if `raw_query` already has `LIMIT`.
- **Time filtering**: bake time clauses into `raw_query` (e.g. `WHERE \`@timestamp\` > NOW() - INTERVAL 1 DAY`). Runtime time-range overrides aren't wired through yet.

## Pitfalls (do not do these)

- **Don't loop `execute_visualization` over a dashboard's panels.** Use `execute_dashboard(dashboard_id)` — one call, parallel fan-out. A 16-panel loop is ~33 sequential HTTP calls instead of one.
- **Don't expect `update_*` to merge lists.** PATCH replaces lists wholesale. To add a panel: fetch current `panels`, append, send the full updated list back. Same for `tags`.
- **Don't try to update `id`, `schema_version`, `created_at`, or `created_by`.** The server silently ignores writes to these.
- **Don't set `chart.type: "metric"` without `visualization_mode: "table"`.** The metric renderer reads from `data["rows"][0]`; without table mode the dispatch goes to chart-rendering instead.
- **Don't name SQL columns with characters that need re-quoting** — keep `AS` aliases simple (`feature`, `denials`, `hour`), match them in `mapping.x` / `mapping.y` verbatim.
- **Don't assume `mapping.x` and `mapping.y` are auto-set from SQL `AS` aliases.** They are NOT — the fallback uses column *position + type*, not names. If you need control, set `mapping` explicitly.
- **Don't catch a panel error and continue silently.** `execute_dashboard` puts errors in `panel["error"]` so the dashboard can ship partially-broken. Render an error placeholder at the panel's layout slot; don't skip it (the layout collapses).
- **Don't use natural-language column names with spaces unless you must.** They work (use backticks: ``` `Hour of day` ```) but make `mapping` strings fragile.

## Discovering the user's schema

Before generating SQL, fetch the dataset schema rather than guessing column names:

```python
schema = sdk.get_dataset_schema("license_events")
# schema is a list of {"name", "type"} entries
```

If you don't know which dataset to query, list them first: `sdk.get_datasets()`.

## Full config reference

`title`, `source.kind`, `source.index`, `chart.type`, and (for `kind=="sql"`) `source.sql.raw_query` are required. Everything else is server-defaulted. Fields you can set explicitly:

### Top-level

```text
title                 str           required
description           str | null    null
source                object        required (see below)
chart.type            enum          required (bar|horizontalBar|line|area|scatter|pie|heatmap|metric|gauge)
visualization_mode    enum          "chart"  (or "table" / "metric")
mapping               object        {x:null, y:[], series_split_by:null}
options               object        all-null (see below)
filters               array         []         SAVED but not yet applied at execute time
time_range            obj | null    null       SAVED but not yet applied at execute time
render                obj | null    null       full-ECharts escape hatch
tags                  str[]         []
extensions            object        free-form metadata; server does not interpret it
```

### `source.*`

```text
source.kind             "sql" | "querydsl" | "promql"   only "sql" wired through execute today
source.index            str                              dataset name
source.connection_id    str | null                       for connector-backed sources
source.connector_id     str | null                       for connector-backed sources
source.sql.raw_query    str                              required when kind=="sql"
source.sql.limit        int        50                    cap applied if raw_query has no LIMIT
source.sql.offset       int        0                     paginated execution
source.sql.dimensions   array      []                    reserved for builder mode — leave empty
source.sql.metrics      array      []                    reserved for builder mode
source.sql.order_by     array      []                    reserved for builder mode
```

### `options.*` (chart-type dependent)

```text
options.legend.show              bool                    all chart types
options.legend.position          "top"|"right"|"bottom"|"left"
options.bar_max_width            int (pixels)            bar / horizontalBar
options.pie_donut_ratio          float                   pie (0.0 = solid; 0.55 = donut)
options.metric_formatting.prefix string                  metric / gauge
options.metric_formatting.suffix string                  metric / gauge
options.metric_formatting.decimals             int
options.metric_formatting.thousands_separator  bool
options.metric_formatting.abbreviate           bool      "184K" instead of "184,250"
```

### `mapping.*`

```text
mapping.x                str | null    fallback: first non-numeric column
mapping.y                str[]         fallback: first numeric column
mapping.series_split_by  str | null    REQUIRED for heatmap (cannot be inferred)
```

### `filters[*]` (saved only; not yet applied)

```text
filters[].id               str    required
filters[].field            str    required — RAW identifier, no quoting (gateway handles dialect)
filters[].operator         enum   is | is_not | is_one_of | is_not_one_of |
                                  is_between | is_not_between | exists | does_not_exist
filters[].value            any    operand (is_between takes [lo, hi] or {from, to})
filters[].enabled          bool   true
filters[].is_time_filter   bool   false
filters[].query_type       enum   "sql" | "querydsl" | null
filters[].index            str    null
```

**Identifier convention:** always pass `field` as a raw column name, never pre-quoted.
The gateway quotes per dialect at execute time (backticks for MySQL/BigQuery, double
quotes for Snowflake/Oracle/native). Pre-quoting (e.g. `` "`feature_name`" `` or
`'"feature_name"'`) is tolerated server-side for back-compat but is the WRONG idiom
for new code — it ties the filter to a specific connector and breaks if the viz is
ever re-pointed at a different source.

### `time_range`

```text
{"kind": "absolute", "from": "2026-04-01T00:00:00Z", "to": "2026-05-01T00:00:00Z"}
{"kind": "relative", "expression": "now-7d"}
```

(Currently saved on the spec but not applied at execute time. Bake equivalent clauses into `raw_query`.)

### `render` (full ECharts escape hatch)

When the typed config can't express a chart, drop down to a full ECharts dict:

```text
render.mode             "echarts_injection"
render.echarts_option   object       full ECharts JSON
render.column_mapping   object       maps series fields to data columns so re-execution binds correctly
```

Use sparingly — once you inject, `to_echarts_option` is no longer managing the chart.

## Fine-grained config example

When `chart.type` alone isn't enough — explicit mapping, legend position, bar width cap, metric formatting, tags, description, donut hole ratio — see [`advanced_chart_config.py`](advanced_chart_config.py). Each knob has an inline comment explaining what it does and when to set it.

## Where to find more

- [`docs/dashboards.md`](../../docs/dashboards.md) — full feature guide (quickstart, layout, troubleshooting, request/response formats, **full configuration reference**)
- [`docs/sdk_methods.md`](../../docs/sdk_methods.md) — per-method reference for every viz/dashboard call
- [`create_and_render.py`](create_and_render.py) — runnable end-to-end flow (5 panels, parallel execute, layout-aware HTML render)
- [`advanced_chart_config.py`](advanced_chart_config.py) — every config knob exercised with inline annotations
- [`common/render.py`](common/render.py) — reference CSS-Grid + ECharts renderer to copy
