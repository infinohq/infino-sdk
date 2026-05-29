# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-05-29

Schema-cleanup release that consolidates the visualization spec around
a single canonical shape per concept and ships a stable response-binding
envelope so renderers no longer have to resolve the gateway's SQL alias
formula themselves. Existing payloads continue to work — the gateway
migrates legacy field shapes on every read.

### Added (gateway-side, transparent to existing callers)

- **`metadata.binding`** — every successful `execute_visualization`
  response now carries `{x, y[], series, value}` under
  `metadata.binding`. Single source of truth for chart renderers: read
  `binding.x` / `binding.y[0]` / `binding.value` to find the response
  column instead of reconstructing the metric's SQL alias yourself
  (`sum_<col>` / `avg_<col>` / `count`).
  - Fixes the "blank-bar" bug where renderers looked up the input
    column (`licenses`) in a response that actually contained the
    aggregation alias (`sum_licenses`).
  - For `bar` / `horizontalBar` / `line` / `area` charts with
    `source.sql.raw_query` set, `binding.y` lists every `mapping.y`
    entry that matches a real response column — hand-written multi-
    aggregation SQL (`SELECT x, AVG(y) AS avg_y, MAX(y) AS max_y`)
    renders as multi-series with no manual binding work.
  - Source-kind-agnostic envelope — when QueryDSL / PromQL builder
    modes ship, the gateway populates the same shape.
  - `InfinoSDK.to_echarts_option(viz, data)` now reads only
    `metadata.binding` and never the saved viz spec for column
    resolution. See [Response contract — metadata.binding](docs/dashboards.md#response-contract--metadatabinding).
- **`source.sql.order_by[]` accepts three entry shapes:**
  - `{column, direction}` — column is either a real schema column or
    an aggregation alias the gateway generates (`count`, `sum_<col>`,
    `avg_<col>`).
  - `{column, function, direction}` — gateway emits the aggregate
    directly, e.g. `ORDER BY SUM("revenue") DESC`. Recognised
    functions: `count` / `sum` / `avg` / `min` / `max`; unknown names
    emit `order_by_function_unknown` and fall back to the bare column.
  - `{metric_id, direction}` — resolves to the matching
    `sql.metrics[].id` and orders by its alias. Unresolved ids emit
    `order_by_metric_id_unresolved` and the entry is skipped.
- **`mapping.x.bucket`** — Builder-mode time bucketing nested inside
  `mapping.x` (`{column, bucket}`). Set `bucket` to one of `minute` /
  `hour` / `day` / `week` / `month` / `quarter` / `year`; gateway
  emits dialect-specific truncation: `DATE_TRUNC` for ANSI / CoreDB /
  Postgres / Snowflake, `TIMESTAMP_TRUNC` for BigQuery, per-
  granularity `DATE_FORMAT` / `DATE` / `MAKEDATE` for MySQL. ISO 8601
  Monday-start week boundary across all engines. Applies to SELECT,
  GROUP BY, and ORDER BY uniformly. The legacy sibling
  `mapping.x_bucket` is accepted on input and folded in on read.
- **Response `metadata.warnings[]`** — list of `{code, message}`
  advisories for silent-fail Builder configs: missing `mapping.x`,
  `heatmap` without `mapping.series`, `mapping.y` set on an
  aggregating chart, `raw_query` colliding with Builder fields,
  unrecognized `connector_id`, unknown `order_by[].function`,
  unresolved `order_by[].metric_id`, plus drift codes
  (`unknown_aggregation_function`, `multi_metric_truncated`,
  `multi_y_truncated`, `order_by_column_unrecognized`,
  `high_cardinality_no_top_n`,
  `top_n_other_bucket_incompatible_with_bucket`, `top_n_zero_ignored`,
  `top_n_without_other_bucket_use_limit`,
  `mapping_y_ignored_for_aggregating_chart`,
  `metric_column_unused_with_count_aggregation`). Warnings are
  advisory — the query still runs. See
  [Builder-mode warnings](docs/dashboards.md#builder-mode-warnings).
- Runtime `filters[]` tolerate missing `id` and missing `value` for
  `exists` / `does_not_exist`. Server stamps a fresh uuid when `id` is
  absent (dedupe is keyed by `field`, not `id`); no-value operators
  ignore `value` entirely. Minimum body becomes
  `{field, operator: "exists", enabled: true}`.
- `mapping.x` and `mapping.y` are optional for `chart.type` `metric`
  and `gauge`. Gateway emits `SELECT <agg> FROM <table>` and ignores
  the axes; previously the schema rejected such payloads.
- Row-mode column types (raw `SELECT a, b` against local CoreDB
  indexes) now report `number` / `boolean` correctly even when CoreDB
  hands the gateway `data_type: "String"`. Gateway sniffs sampled row
  values for string-declared columns and overrides when every non-null
  sample is numeric or boolean.
- `COUNT(*)` alias is dialect-quoted (`as "count"` /
  `` as `count` ``) so the response column name preserves case.
  Previously the planner normalized the unquoted alias to `COUNT`
  (uppercase), breaking consumers that keyed off it.

### Changed — schema cleanup (canonical shapes)

- **`mapping.series_split_by` → `mapping.series`.** Aligns with
  Evidence, ECharts, Superset (`series_columns`), and ggplot's `color`
  channel. The old name is accepted on input and migrated; response
  `metadata.binding` now publishes `series` instead of
  `series_split_by`.
- **`mapping.x: "col"` + `mapping.x_bucket: "month"` →
  `mapping.x: {column: "col", bucket: "month"}`.** Nests time-
  truncation granularity inside the X-dimension where Vega-Lite,
  ThoughtSpot, and LookML put it. The bare-string form and the legacy
  sibling field are both accepted on input and folded into the object
  form on read. `mapping.top` / `mapping.other_bucket` stay as
  siblings (Metabase / Superset convention).
- **`visualization_mode` field removed; `chart.type: "table"` added.**
  The legacy enum was redundant with `chart.type` — every combination
  that mattered (`table`, `metric`, `gauge`) is expressible via
  `chart.type` alone. Saved vizzes with the legacy field are migrated
  silently on read. New payloads should set `chart.type` directly and
  omit `visualization_mode`.
- **`sql.dimensions[]` retired; Top-N + Other moves to `mapping`.**
  Chart-level concepts (top, other_bucket, date_interval) now live on
  `mapping`:
  - `sql.dimensions[].top` → `mapping.top`
  - `sql.dimensions[].other_bucket` → `mapping.other_bucket`
  - `sql.dimensions[].date_interval` → `mapping.x.bucket`

  Gateway migrates legacy payloads on read. UI no longer writes
  `sql.dimensions[]`. Setting `mapping.top` without
  `mapping.other_bucket: true` warns with
  `top_n_without_other_bucket_use_limit`.
- **`mapping.y` scoped to `scatter` / `table` only.** Previously
  `mapping.y[0]` doubled as the metric input column for aggregating
  charts — the same value the user also wrote into `metrics[0].column`.
  Now:
  - `scatter`: `mapping.y[0]` is the raw y-axis column (no aggregation).
  - `table`: `mapping.y` is the SELECT column list (empty → `SELECT *`).
  - everything else (bar / line / area / pie / heatmap / metric / gauge):
    `mapping.y` is **ignored** for SQL emission. The y axis comes from
    `metrics[]` only. `mapping.y` is still preserved on the stored
    config and used for `metadata.binding` derivation in raw-query
    mode.

  Setting `mapping.y` on an aggregating chart emits
  `mapping_y_ignored_for_aggregating_chart`. The legacy
  `y_axis_unused_with_count_aggregation` warning is replaced with
  `metric_column_unused_with_count_aggregation` which reads from
  `metrics[0]` directly.
- **`order_by[]` docs reordered** to lead with the rename-safe
  `metric_id` form. The alias-by-column form (`column: "sum_revenue"`)
  still works but is documented as the legacy idiom.

### Changed — warning codes

- `missing_series_split_by_for_heatmap` → `missing_series_for_heatmap`.
- `top_n_other_bucket_incompatible_with_x_bucket` →
  `top_n_other_bucket_incompatible_with_bucket`.
- `raw_query_overrides_builder_fields` — narrowed trigger and clearer
  message. Previously fired whenever any `mapping.*` field was set
  alongside `raw_query`. Now fires only when truly-ignored fields are
  populated (`source.sql.metrics`, `source.sql.order_by`,
  `mapping.x.bucket`, `mapping.top`, `mapping.other_bucket`). The
  message explicitly calls out that `mapping.x` / `mapping.y` /
  `mapping.series` are still honoured for binding derivation.
- Warning *messages* throughout the rewriter reference the new field
  paths (`mapping.x.bucket`, `mapping.series`).

### Fixed — runtime contract

- **`mapping.y` is preserved verbatim** on aggregating chart types.
  The previous create/update path silently wiped `mapping.y` to `[]`
  for any aggregating chart and synthesized a phantom `metrics[0]`
  entry from the wiped column. That destroyed consumer input,
  suppressed the documented `mapping_y_ignored_for_aggregating_chart`
  warning, broke raw-mode multi-Y, and stored configs that diverged
  from POST bodies. Now `mapping.y` round-trips intact; the warning
  fires at execute time when set on a chart type that ignores it.
- **No phantom `metrics[0]` synthesis.** Stored configs faithfully
  reflect the request body.
- **Metric alias unquoted in `binding.y`.** When `metrics[].column` is
  schema-quoted (e.g. `"\"dayOfWeek\""`), the gateway now emits
  `binding.y[0] = "sum_dayOfWeek"` instead of `sum_"dayOfWeek"` — so
  the renderer's `row[binding.y[0]]` lookup resolves. Same fix applied
  to `order_by` alias resolution.
- **`metrics[].function` validation** — function was previously
  uppercased and emitted directly as a SQL function name, so a typo
  like `"nonsense_xyz"` produced `NONSENSE_XYZ("col")` and CoreDB
  returned garbage rows with no error. Now validated against the
  allow-list `{count, sum, avg, min, max, none}`; unknown values emit
  `unknown_aggregation_function` and fall back to `count`.
- **Time-bucketed columns now carry an `AS` alias** —
  `mapping.x.bucket` used to emit a bare `DATE_TRUNC(...)` /
  `TIMESTAMP_TRUNC(...)` expression, so the response column name fell
  back to dialect defaults (`f0_` on BigQuery, the literal expression
  string on native CoreDB). Renderers couldn't bind to the column.
  The SELECT clause now wraps the expression with `AS "<x_axis>"` so
  the response column name matches `mapping.x.column` regardless of
  bucketing.
- **`contains` filter operator** — previously documented but rejected
  at execute time with `unsupported operator: contains`. Now
  implemented using dialect-safe `LIKE '%value%'` with `%`, `_`, `\`,
  and `'` escaped so the substring is matched literally.
- Narrowed the `y_axis_unused_with_count_aggregation` warning: no
  longer fires for `function: "none"` (explicit no-aggregation) or for
  scatter charts (y is a raw column by design).

### Migration

The gateway's read-time normalization runs on every GET / LIST /
execute so existing stored visualizations keep working without caller
changes:

- renames `mapping.series_split_by` → `mapping.series` (only when
  `mapping.series` is unset);
- collapses `mapping.x: "col"` + sibling `mapping.x_bucket: "g"` into
  `mapping.x: {column: "col", bucket: "g"}`;
- back-fills `chart.type: "table"` / `"metric"` from a legacy
  `visualization_mode` field when `chart.type` isn't already set;
- moves `sql.dimensions[]` chart-level fields onto `mapping` and
  clears `sql.dimensions[]`;
- preserves any already-set canonical field on the inbound payload
  (migration is idempotent).

Legacy keys are still accepted on input indefinitely. New SDK
examples and `docs/dashboards.md` use the canonical shape; code that
still emits the legacy names continues to work.

A small number of stored visualizations from before `mapping.y` was
scoped to scatter / table may have had `mapping.y[0]` as the metric
column with an empty `metrics[]`. With the phantom-synthesis path
removed, these now emit `COUNT(*)` at execute time and surface
`mapping_y_ignored_for_aggregating_chart`. Resave via the UI (which
emits canonical `metrics[].column`) to restore the intended
aggregation.

## [0.6.0] - 2026-05-25

### Added (SDK surface)
- `execute_visualization(viz_id, filters=...)` — optional `filters` kwarg
  applies runtime filter chips on top of any filters saved on the
  visualization. The gateway AND-merges them into the executed SQL via the
  server-side rewriter. Eight operators supported:
  `is`, `is_not`, `is_one_of`, `is_not_one_of`, `exists`, `does_not_exist`,
  `is_between`, `is_not_between`. For `is_between` time filters, `value` is
  either `[lo, hi]` (numeric) or `{"from": ..., "to": ...}` (time-range).
- `execute_dashboard(dashboard_id, filters=...)` — same kwarg, applied to
  every panel's `execute_visualization` call in the parallel fanout.
- `execute_visualization(viz_id, time_range={"from", "to"})` — runtime
  time-range override applied as a synthetic `is_between` filter on the
  viz's time column. Send ISO-8601 strings or epoch-ms numbers (UTC).
  Absolute timestamps only; relative syntax (e.g. `"now-1h"`) is not
  supported.
- `execute_dashboard(dashboard_id, time_range=...)` — same kwarg, applied
  to every panel in the parallel fanout.
- Response metadata now surfaces `filters_applied` (fields the rewriter
  injected) and `filters_skipped` (`{field, reason}` for any the rewriter
  couldn't safely inject — e.g. parser edge cases). Unrecognised filters
  never fail the execute call; the original SQL still runs.
- `_normalize_filter()` helper auto-fills `id` (uuid4), `enabled` (True),
  `is_time_filter` (False), `query_type` (None), `index` (None) so callers
  only need to specify `field`, `operator`, and `value`.
- `source.sql.time_column` field — declare which column the runtime
  time-range filter targets. Defaults to `@timestamp` (native CoreDB
  convention). Set explicitly for connector vizzes whose time column is
  e.g. `created_at`.

### Added (gateway-side, transparent to existing callers)
- `source.sql.order_by[]` is now honored in Builder mode. Unlocks the
  "top N by metric" pattern via `ORDER BY <metric_alias> DESC`. Each entry
  is `{column, direction}` where `column` may be a real schema column OR an
  aggregation alias the gateway generates (`count`, `sum_<col>`,
  `avg_<col>`). Falls back to `ORDER BY <x>` when omitted. See
  [Top-N pattern](docs/dashboards.md#top-n-pattern) for the full example.
- Dialect-aware identifier quoting in Builder mode for **all** dimensional
  columns (previously only the table was quoted dialect-aware). Fixes
  CoreDB's null-bucket case-normalization bug and BigQuery's "Cannot GROUP
  BY literal values" / "Unexpected string literal" errors on Builder-mode
  payloads. Send identifiers raw — the gateway quotes per connector
  dialect.
- Expanded column-type normalization in execute responses to handle
  BigQuery (`INT64`, `FLOAT64`, `BIGNUMERIC`), MySQL (`BIGINT`,
  `TINYINT`, `SMALLINT`, `MEDIUMINT`), Snowflake (`TIMESTAMP_LTZ`,
  `TIMESTAMP_NTZ`, `TIMESTAMP_TZ`, parameterized `NUMBER(38,2)`),
  Postgres (`REAL`, `MONEY`, `UUID`, `TIMESTAMPTZ`), and parameterized
  types (`VARCHAR(255)`, `INT(11)`, `DOUBLE PRECISION`). Previously these
  all fell to `"string"` in response metadata, silently breaking chart
  rendering for numeric columns.

### Changed
- Saved top-level `time_range` on a visualization spec was previously stored
  but ignored at execute time. **It is now applied** — flag this if any of
  your saved vizzes have a populated `time_range`.

### Fixed
- Dashboard top-level time picker now affects SQL visualizations the same way
  it has always affected QueryDSL visualizations. Previously the picker's
  value was dropped on the floor for SQL panels.
- PATCH and PUT on dashboards/visualizations now re-apply server defaults
  after the merge/replace. Previously a PATCH like
  `{ "panels": [{ "viz_id": "x" }] }` stripped server-stamped panel
  defaults (`kind`, `id`, `layout`) because RFC 7396 JSON Merge Patch
  replaces arrays wholesale. Root cause of the
  `Cannot read properties of undefined (reading 'x')` error some callers
  saw when rendering dashboards that had been patched in-place.

### Documentation
- Builder-mode docs in `docs/dashboards.md` — create visualizations
  without writing SQL by setting `mapping.x` / `mapping.y[]` /
  `aggregation_type` and leaving `source.sql.raw_query` null. The gateway
  generates dialect-aware SQL server-side.
- Aggregation cheat sheet: `count`, `sum`, `avg`, `none` — when to use which.
- Top-N pattern example covering the `order_by` alias contract.
- New `examples/dashboards/builder_mode.py` — runnable end-to-end example
  showing both raw-SQL and Builder-mode visualization creation in a single
  dashboard, plus runtime filter and time-range application.

### Important contracts
- **Filter identifiers are raw** — send `"feature_name"`, never
  `` "`feature_name`" `` or `"\"feature_name\""`. The gateway quotes per
  the connector dialect (backticks for MySQL/BigQuery, double-quotes
  elsewhere). Pre-quoting ties your filter to a specific dialect and
  breaks portability. Same convention applies to `mapping.x/y/series_split_by`
  and `metrics[].column` in Builder mode.
- Relative time syntax in `time_range` (e.g. `"now-1h"`) is **not yet
  supported**. Send absolute ISO-8601 or epoch-ms timestamps; the SDK does
  not expand relative shortcuts client-side. Coming in a follow-up.

## [0.5.0] - 2026-05-15

### Added
- Visualization CRUD:
  - `create_visualization(spec)` — lenient create; server fills defaults so
    minimum body is
    `{title, source: {kind, index, sql: {raw_query}}, chart: {type}}`
  - `get_visualization(id)`, `list_visualizations(limit=, offset=)`,
    `delete_visualization(id)`
  - `update_visualization(id, partial)` — send only the fields you want
    to change; `id`, `schema_version`, `created_at`, and `created_by`
    are immutable. (Wire format: RFC 7396 JSON Merge Patch.)
- Dashboard CRUD mirroring the viz surface:
  - `create_dashboard(spec)`, `get_dashboard(id)`,
    `list_dashboards(limit=, offset=)`, `update_dashboard(id, partial)`,
    `delete_dashboard(id)`
  - Server auto-flows panels into a 2-column grid when explicit `layout`
    is omitted; explicit per-panel `layout: {x, y, w, h}` is preserved
- Plot-ready execution:
  - `execute_visualization(viz_id)` — returns `{columns, rows, metadata}`
    with type-normalised column descriptors
    (`string` / `number` / `boolean` / `date` / `null`)
  - `execute_dashboard(dashboard_id)` — fans out all panels in parallel via
    `ThreadPoolExecutor`; returns enriched per-panel data + viz config +
    layout in one call. Per-panel errors are isolated — one bad panel
    doesn't fail the whole request.
- `to_echarts_option(viz, data)` helper that maps the typed visualization
  plus its executed rows into plain ECharts JSON. Covers `bar`,
  `horizontalBar`, `line`, `area`, `pie`, `heatmap`, `scatter`; dispatches
  to `kind: "table"` for table-mode vizzes and `kind: "metric"` for
  single-value displays. Numeric-aware axis sort (no `"10" < "9"`
  surprises); type-aware fallback picks the first numeric column for Y
  when `mapping` is empty.
- Runnable end-to-end example package `examples/dashboards/` modelled
  on the existing `examples/fino_nl_chat/` folder layout — shared
  helpers (`config`, `logging_config`, `render`) live in
  `dashboards/common/`, and `dashboards/create_and_render.py` walks
  through creating five visualizations, bundling them into a
  dashboard, executing every panel in parallel, and rendering a
  layout-aware composite HTML page via CSS Grid honouring each
  panel's stored `{x, y, w, h}`. The example SQL targets a license-
  management dataset (`flexlm_cdslmd.rel` +
  `cdn_product_feature_mapping.rel`) so the flow covers a JOIN-based
  query, a heatmap, a metric card, a horizontal bar, and a pie in
  one go. Override `INFINO_DEMO_DATASET` /
  `INFINO_DEMO_MAPPING_DATASET` to point at your own indices.
- Companion example `examples/dashboards/advanced_chart_config.py`
  exercising every visualization config knob with inline annotations:
  `description`, `tags`, explicit `mapping`, `options.legend`,
  `options.bar_max_width`, `options.pie_donut_ratio`,
  `options.metric_formatting` (prefix / suffix / decimals /
  thousands_separator / abbreviate), and `source.sql.limit` / `offset`.
- Agent-friendly rules file `examples/dashboards/AGENTS.md` (read by
  Claude Code, Cursor, aider, Cline, Codex CLI, OpenHands) carrying
  task→SDK-call mappings, minimal chart skeletons per type, decision
  rules, common pitfalls, and the full config-field reference. Drop
  the SDK into any agent-driven workspace and the agent will pattern-
  match correct visualization code.
- Full configuration reference in `docs/dashboards.md` covering every
  field a visualization spec can carry (top-level, `source.*`,
  `mapping.*`, `options.*`, `filters[*]`, `time_range`, `render`) with
  types, defaults, and effects.
- README section "Visualize – Build and Execute Visualizations" covering
  create / update / execute / manage / dashboard composition.

### Notes
- Currently supports `source.kind == "sql"` with a non-empty `raw_query`.
  `querydsl` / `promql` source slots exist in the schema for future
  support. Saved `filters` and `time_range` are accepted on the spec but
  not yet applied at execute time — bake equivalent clauses into the SQL
  string for now.
- Requires the Infino Gateway build with the visualization/dashboard
  endpoints (lenient POST, execute, PATCH). Earlier gateway builds
  return 405.
- The `to_echarts_option` output is structurally correct but visually
  plain (no theme / colour palette / number formatting). Deep-merge your
  styling on top of the returned ECharts option dict, or apply the viz's
  `options.metric_formatting` (`prefix`, `suffix`, `decimals`,
  `abbreviate`, `thousands_separator`) yourself in the renderer.

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
