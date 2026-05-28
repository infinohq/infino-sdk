# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — Tranche 4S: stop wiping `mapping.y` + synthesizing phantom metrics

### Fixed (runtime contract enforcement)

- **`mapping.y` is now preserved verbatim** on aggregating chart types.
  The previous create/update migration silently wiped `mapping.y` to
  `[]` for any aggregating chart, then synthesized a phantom
  `metrics[0]` entry from the wiped column. Three problems with the old
  behavior:
  - **Destroyed consumer input** without surfacing the documented
    `mapping_y_ignored_for_aggregating_chart` warning (the warning
    fires only when `mapping.y` is non-empty at execute time, so the
    wipe silenced it).
  - **Invented data the consumer never sent** — stored configs diverged
    from POST bodies. Anyone fetching the viz to edit would see SQL
    they didn't author.
  - **Broke raw-mode multi-Y** — `mapping.y: ["avg_l", "max_l"]` on a
    `raw_query` bar chart got wiped to `[]`, killing the multi-series
    binding expansion that the docs promise.
- **Phantom `metrics[0]` synthesis removed.** Stored configs now
  faithfully reflect the request body. If `mapping.y` is set on an
  aggregating chart, the rewriter emits the documented warning at
  execute time; the field is not destructively rewritten.

### Behavior change for existing legacy vizzes

A small number of stored vizzes from before Tranche 2 may have had
`mapping.y[0]` as the metric column with empty `metrics[]`. With the
phantom-synthesis path removed, these will now emit `COUNT(*)` at
execute time and surface `mapping_y_ignored_for_aggregating_chart`
warning rather than silently being rewritten. Resave via the UI (which
emits canonical `metrics[].column`) to restore the intended aggregation.

## [Unreleased] — Tranche 4: chart-config vocabulary cleanup

Aligns the visualization schema with industry conventions for SDK-first
analytics tools (Evidence, ECharts, Cube.dev, Superset). Two renames; the
gateway migrates legacy payloads on read so existing saved visualisations
keep working without caller changes.

### Changed (visualization schema — back-compat reads, canonical writes)
- **`mapping.series_split_by` → `mapping.series`.** Aligns with Evidence,
  ECharts, Superset (`series_columns`), and ggplot's `color` channel
  concept. The old name is accepted on input and migrated; the response
  `metadata.binding` now publishes `series` instead of `series_split_by`.
- **`mapping.x: "col"` + `mapping.x_bucket: "month"` →
  `mapping.x: {column: "col", bucket: "month"}`.** Nests the
  time-truncation granularity inside the X-dimension where Vega-Lite,
  ThoughtSpot, and LookML put it. The bare-string form and the legacy
  sibling field are both accepted on input and folded into the object
  form by `apply_visualization_defaults`. `mapping.top` and
  `mapping.other_bucket` stay as siblings (Metabase / Superset
  convention — query-shape concerns rather than per-column properties).

### Changed (warning codes)
- `missing_series_split_by_for_heatmap` → `missing_series_for_heatmap`.
- `top_n_other_bucket_incompatible_with_x_bucket` →
  `top_n_other_bucket_incompatible_with_bucket`.
- Warning *messages* throughout the rewriter reference the new field
  paths (`mapping.x.bucket`, `mapping.series`).

### Migration

No caller action required. Existing payloads round-trip through the
gateway's `apply_visualization_defaults` pass which:
- renames `mapping.series_split_by` → `mapping.series` (only when
  `mapping.series` is unset);
- collapses `mapping.x: "col"` + sibling `mapping.x_bucket: "g"` into
  `mapping.x: {column: "col", bucket: "g"}`;
- preserves an already-set `mapping.series` / `mapping.x.bucket` on the
  inbound payload.

The legacy keys are still accepted on input indefinitely (the migration
is idempotent). New SDK examples and the dashboards.md docs use the
canonical Tranche-4 shape; old code that still emits the legacy names
continues to work.

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
- `metadata.binding` — every successful `execute_visualization` response
  now carries `{x, y[], series_split_by, value}` under `metadata.binding`.
  This is the single source of truth for any consumer rendering a chart
  from the response: read `binding.x` / `binding.y[0]` / `binding.value`
  to find the response column, instead of resolving the metric's SQL
  alias yourself (`sum_<col>` / `avg_<col>` / `count`).
  - Fixes the long-standing "blank-bar" bug where renderers looked up the
    `mapping.y` input column (`licenses`) in a response that actually
    contained the aggregation alias (`sum_licenses`).
  - Source-kind-agnostic envelope — when QueryDSL / PromQL builder modes
    ship, the gateway will populate the same shape, so renderers written
    against `binding` keep working without changes.
  - `InfinoSDK.to_echarts_option(viz, data)` now reads only
    `metadata.binding` and never the saved viz spec for column resolution.
    See [Response contract — metadata.binding](docs/dashboards.md#response-contract--metadatabinding).
- `source.sql.order_by[]` is now honored in Builder mode, and accepts
  three entry shapes:
  - `{column, direction}` — `column` may be a real schema column OR an
    aggregation alias the gateway generates (`count`, `sum_<col>`,
    `avg_<col>`).
  - `{column, function, direction}` — gateway emits the aggregate directly,
    e.g. `ORDER BY SUM("revenue") DESC`. Recognised functions: `count` /
    `sum` / `avg` / `min` / `max`; unknown function names emit
    `order_by_function_unknown` and fall back to ordering by the bare
    column.
  - `{metric_id, direction}` — resolves to the matching
    `sql.metrics[].id` and orders by its alias. Unresolved ids emit
    `order_by_metric_id_unresolved` and the entry is skipped.

  Falls back to `ORDER BY <x>` when `order_by` is empty / absent. See
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
- `mapping.x_bucket` — Builder-mode time bucketing. Set to one of
  `minute` / `hour` / `day` / `week` / `month` / `quarter` / `year` and
  the gateway emits dialect-specific truncation: `DATE_TRUNC` for ANSI /
  CoreDB / Postgres / Snowflake, `TIMESTAMP_TRUNC` for BigQuery, and
  per-granularity `DATE_FORMAT` / `DATE` / `MAKEDATE` for MySQL (no
  `DATE_TRUNC` exists there). Applies to SELECT, GROUP BY, and ORDER BY
  uniformly. ISO 8601 Monday-start week boundary across all engines.
  Oracle returns a 400 with a workaround hint until per-engine support
  lands.
- Response `metadata.warnings[]` — list of `{code, message}` advisories
  for silent-fail Builder configs: missing `mapping.x` for a chart type,
  `heatmap` without `series_split_by`, `mapping.y` set with COUNT
  aggregation, `raw_query` colliding with Builder fields, unrecognized
  `connector_id`, unknown `order_by[].function`, unresolved
  `order_by[].metric_id`, plus `sql.dimensions[]` silent-drop codes
  (`x_bucket_conflicts_with_date_interval`,
  `dimension_date_interval_ignored`,
  `dimension_custom_expression_ignored`,
  `top_n_other_bucket_unsupported_on_non_x`,
  `top_n_without_other_bucket_use_limit`,
  `top_n_other_bucket_incompatible_with_x_bucket`,
  `top_n_zero_ignored`), plus consumer-facing config drift codes
  (`unknown_aggregation_function`, `multi_metric_truncated`,
  `multi_y_truncated`, `order_by_column_unrecognized`,
  `high_cardinality_no_top_n`). Warnings are advisory — the query still
  runs. See [Builder-mode warnings](docs/dashboards.md#builder-mode-warnings).
- Runtime `filters[]` now tolerate missing `id` and missing `value` for
  `exists` / `does_not_exist`. Server auto-stamps a fresh uuid for any
  filter without an `id` (dedupe is keyed by `field`, not `id`), and the
  no-value operators ignore `value` entirely — you can post
  `{field, operator: "exists", enabled: true}` as the full filter body.
- `mapping.x` and `mapping.y` are optional for `chart.type` `metric` and
  `gauge`. The gateway emits `SELECT <agg> FROM <table>` and ignores the
  axes; previously the schema rejected payloads that omitted them.
- `sql.dimensions[].date_interval` is now honoured as a fallback for
  `mapping.x_bucket`. When the dimension's `column` matches `mapping.x`
  and `mapping.x_bucket` is unset, the granularity (`"day"` / `"hour"` /
  etc.) drives the same dialect-specific `DATE_TRUNC` / `TIMESTAMP_TRUNC`
  / `DATE_FORMAT` rewrite. `mapping.x_bucket` wins on conflict and emits
  `x_bucket_conflicts_with_date_interval`.
- `sql.dimensions[].top` + `other_bucket: true` on the X dimension now
  triggers a CASE-rewrite that aggregates non-top values into a literal
  `'Other'` bucket. See [Top-N + Other rollup](docs/dashboards.md#top-n--other-rollup).
  Mutually exclusive with `mapping.x_bucket`; `top` without
  `other_bucket: true` is the same as vanilla top-N from
  `sql.order_by + sql.limit` and emits a warning pointing at those
  fields.
- Silent-drop coverage for `sql.dimensions[]` extended with three new
  advisory codes: `dimension_date_interval_ignored` (interval set on a
  non-X column), `dimension_custom_expression_ignored` (custom SQL
  expression — switch to `raw_query`), and
  `top_n_other_bucket_unsupported_on_non_x` (rollup requested on a
  non-X dimension).
- Row-mode column types (raw `SELECT a, b` against local CoreDB indexes)
  now report `number` / `boolean` correctly even when CoreDB hands the
  gateway `data_type: "String"`. Gateway sniffs sampled row values for
  string-declared columns and overrides when every non-null sample is
  numeric or boolean. Aggregation paths are unaffected (CoreDB returns
  correct `Integer` / `Float` for those).
- `COUNT(*)` alias is now dialect-quoted (`as "count"` /
  `` as `count` ``) so the response column name preserves the case the
  SQL emitted. Previously the planner normalized the unquoted alias to
  `COUNT` (uppercase), breaking consumers that keyed off the alias.

### Changed
- Saved top-level `time_range` on a visualization spec was previously stored
  but ignored at execute time. **It is now applied** — flag this if any of
  your saved vizzes have a populated `time_range`.
- **`visualization_mode` field removed; `chart.type: "table"` added.** The
  legacy `visualization_mode` enum was redundant with `chart.type` — every
  combination that mattered (`table`, `metric`, `gauge`) is now expressible
  via `chart.type` alone. Saved vizzes with the legacy field are migrated
  silently on read (`visualization_mode: "table"` back-fills
  `chart.type: "table"`; `"metric"` back-fills `chart.type: "metric"`
  when not already a single-value type). New payloads should set
  `chart.type` directly and omit `visualization_mode`. No payload breakage.
- **`sql.dimensions[]` retired; Top-N + Other moves to `mapping`.** The
  array was housing chart-level concepts (top, other_bucket,
  date_interval) in a parallel structure that duplicated `mapping`'s
  job. They now live on `mapping`:
  <ul>
  <li>`sql.dimensions[].top` → `mapping.top`</li>
  <li>`sql.dimensions[].other_bucket` → `mapping.other_bucket`</li>
  <li>`sql.dimensions[].date_interval` → `mapping.x_bucket` (already had
      this alias; now the canonical home)</li>
  </ul>
  Gateway migrates legacy payloads on read — the X-dimension entry's
  fields move into `mapping`, then `sql.dimensions[]` is cleared. New
  payloads should omit `sql.dimensions[]` entirely (or send `[]`).
  Setting `mapping.top` without `mapping.other_bucket: true` warns with
  `top_n_without_other_bucket_use_limit`. UI no longer writes
  `sql.dimensions[]` on save.
- **`mapping.y` scoped to scatter / table only.** Historically `mapping.y[0]`
  carried the metric input column for aggregating charts — the same value
  the user also wrote into `metrics[0].column`. The duplication was the
  single biggest source of "consumer's first hour" confusion. Now:
  <ul>
  <li>`scatter`: `mapping.y[0]` is the raw y-axis column (no aggregation).</li>
  <li>`table`: `mapping.y` is the SELECT column list (empty → `SELECT *`).</li>
  <li>everything else (bar / line / area / pie / heatmap / metric / gauge): `mapping.y` is **ignored**. The y axis comes from `metrics[]` only.</li>
  </ul>
  Saved aggregating-chart vizzes that had `mapping.y[0]` set are migrated
  on read — the column is back-filled into `metrics[0]` (function from
  `aggregationType`, defaulting to `sum`) and `mapping.y` is cleared.
  Setting `mapping.y` on an aggregating chart now emits the
  `mapping_y_ignored_for_aggregating_chart` warning. The old
  `y_axis_unused_with_count_aggregation` warning is replaced with
  `metric_column_unused_with_count_aggregation` which reads from
  `metrics[0]` directly.
- **`order_by[]` docs reordered** to lead with the rename-safe
  `metric_id` form. The alias-by-column form (`column: "sum_revenue"`)
  still works but is now documented as the legacy idiom — it leaks the
  generator's alias formula into the payload.
- **`mapping.series_split_by` semantics clarified.** The field's role
  depends on `chart.type` (pivot for bar/line/area; second categorical
  axis for heatmap; ignored for pie/scatter/metric/gauge/table). Docs
  now spell this out per chart type.

### Fixed
- **`metrics[].function` validation** — `function` was previously
  uppercased and emitted directly as a SQL function name, so a typo like
  `"nonsense_xyz"` would produce `NONSENSE_XYZ("col")` and CoreDB would
  return garbage rows with no error. Now validated against the
  allow-list `{count, sum, avg, min, max, none}`; unknown values emit
  `unknown_aggregation_function` and fall back to `count`.
- **Time-bucketed columns now carry an `AS` alias** — `mapping.x_bucket`
  used to emit a bare `DATE_TRUNC(...)` / `TIMESTAMP_TRUNC(...)`
  expression, so the response column name fell back to dialect defaults
  (`f0_` on BigQuery, the literal expression string on native CoreDB).
  Renderers couldn't bind to the column. Now the SELECT clause wraps the
  expression with `AS "<x_axis>"` so the response column name matches
  `mapping.x` regardless of bucketing.
- **`contains` filter operator** — previously documented but rejected
  at execute time with `unsupported operator: contains`. Now implemented
  using dialect-safe `LIKE '%value%'` with `%`, `_`, `\`, and `'`
  escaped so the substring is matched literally.
- Narrowed the `y_axis_unused_with_count_aggregation` warning: no longer
  fires for `function: "none"` (explicit no-aggregation) or for scatter
  charts (y is a raw column by design).
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
