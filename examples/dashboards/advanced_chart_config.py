"""
Fine-grained chart configuration.

The five-panel example in :mod:`create_and_render` shows the workflow:
create → execute → render. This example shows the *knobs* — every field
you can put on a visualization beyond ``title`` + ``source`` +
``chart.type`` to control how a chart looks and behaves.

Each visualization below has inline comments explaining what the field
does, and which fields are server-defaulted when you omit them.

Required fields (everything else is optional):

    title           (str)            display title
    source.kind     (str)            "sql" | "querydsl" | "promql"
    source.index    (str)            dataset name
    source.sql.raw_query             (str, when kind=="sql")
    chart.type      (str)            bar | horizontalBar | line | area |
                                     scatter | pie | heatmap | metric | gauge

All other fields are server-defaulted — see ``apply_visualization_defaults``
in the gateway for the exact defaults, or just omit a field and inspect
what the server fills.

Usage:
    export INFINO_ACCESS_KEY='your_key'
    export INFINO_SECRET_KEY='your_secret'
    export INFINO_ENDPOINT='https://api.infino.ws'
    python -m examples.dashboards.advanced_chart_config
"""

from __future__ import annotations

import json
import sys

from infino_sdk import InfinoError, InfinoSDK

from .common import (
    DEMO_DATASET,
    DEMO_MAPPING_DATASET,
    get_credentials,
    get_logger,
    setup_logging,
    validate_credentials,
)

logger = get_logger(__name__)


def fine_tuned_bar(dataset: str) -> dict:
    """A bar chart with explicit mapping, legend, bar width cap, tags, and description."""
    return {
        "title": "Top Denied Features (last 30d)",
        # `description` shows up in list views and detail panes.
        "description": "Top 10 features by denial count over the last 30 days. "
                       "Source: license-server denial events.",
        "source": {
            "kind": "sql",
            "index": dataset,
            # `connection_id` (and `connector_id`) are for connector-backed sources
            # (e.g. Snowflake). Omit for native Infino datasets.
            "sql": {
                "raw_query": (
                    f"SELECT `feature_name` AS `Feature`, "
                    f"COUNT(*) AS `Denials` "
                    f"FROM `{dataset}` "
                    f"WHERE `event_type` = 'DENIED' "
                    f"GROUP BY `feature_name` "
                    f"ORDER BY `Denials` DESC "
                    f"LIMIT 10"
                ),
                # `limit` is a server-side row cap applied AFTER `raw_query`
                # if the query itself has no LIMIT. Ignored when raw_query
                # already has LIMIT, as above.
                "limit": 50,
                # `offset` for paginated execution (rarely used).
                "offset": 0,
            },
        },
        "chart": {"type": "bar"},
        # Without `mapping`, the renderer picks "first non-numeric column → X,
        # first numeric → Y". When SQL aliases are well-named, you can omit
        # `mapping` entirely. When you have multiple numeric columns or want
        # to control which is which, set it explicitly:
        "mapping": {
            # Object form: `{column, bucket?}`. Bare-string
            # form is still accepted as input and migrated server-side.
            "x": {"column": "Feature"},
            # Raw-SQL mode: list the response column(s) you want bound
            # to the chart's y-axis. The renderer reads
            # `metadata.binding` (gateway-computed) to resolve columns.
            "y": ["Denials"],
            "series": None,    # only used for heatmap / multi-series
        },
        # The legacy `visualization_mode` field is retired; `chart.type`
        # is the single render-kind discriminator. Use
        # `chart.type: "table"` for raw rows, `"metric"` / `"gauge"`
        # for single-value display.
        "options": {
            # Where the legend sits. `null` (default) hides it.
            "legend": {"show": True, "position": "right"},
            # Cap bar width in pixels so a 3-bar chart doesn't render as
            # huge slabs in a wide panel. `null` lets ECharts auto-size.
            "bar_max_width": 40,
            # Other option fields stay null for a bar chart:
            "metric_formatting": None,
            "pie_donut_ratio": None,
        },
        # `tags` are free-form strings for filtering/grouping in list views.
        "tags": ["licensing", "denials", "top-features"],
    }


def fine_tuned_donut(dataset: str, mapping_dataset: str) -> dict:
    """A donut pie (pie with a hole) showing legend bottom + custom slice ordering via SQL."""
    return {
        "title": "Denials by Primary Stage",
        "description": "Denial volume rolled up to design-flow stage via JOIN "
                       "with the feature-mapping table.",
        "source": {
            "kind": "sql",
            "index": dataset,
            "sql": {
                "raw_query": (
                    f"SELECT m.`Primary Stage` AS `Stage`, "
                    f"COUNT(*) AS `Denials` "
                    f"FROM `{dataset}` f "
                    f"JOIN `{mapping_dataset}` m "
                    f"ON f.`feature_name` = m.`Feature Name` "
                    f"WHERE f.`event_type` = 'DENIED' "
                    f"GROUP BY m.`Primary Stage` "
                    f"ORDER BY `Denials` DESC"
                ),
            },
        },
        "chart": {"type": "pie"},
        "mapping": {
            "x": {"column": "Stage"},   # the slice category
            "y": ["Denials"],           # the slice value (raw-SQL mode)
            "series": None,
        },
        "options": {
            # 0.0 = solid pie, > 0.0 = donut hole.  0.5 = half-donut.
            # Common UI default for "donut" is 0.55.
            "pie_donut_ratio": 0.55,
            "legend": {"show": True, "position": "bottom"},
            "bar_max_width": None,
            "metric_formatting": None,
        },
        "tags": ["licensing", "denials", "stages"],
    }


def fine_tuned_metric(dataset: str) -> dict:
    """A single-number KPI with full formatting: prefix, suffix, abbreviation, separators."""
    return {
        "title": "Estimated Wasted License Spend",
        "description": "Sum of (zero-utilisation features × annual cost). "
                       "Updated daily.",
        "source": {
            "kind": "sql",
            "index": dataset,
            "sql": {
                # Single row, single numeric column — what metric rendering expects.
                "raw_query": (
                    f"SELECT 184250 AS `Estimated Wasted Spend` "
                    f"FROM `{dataset}` LIMIT 1"
                ),
            },
        },
        "chart": {"type": "metric"},
        # `chart.type: "metric"` is sufficient —  retired the
        # legacy `visualization_mode` field; the metric renderer is
        # selected by `chart.type` alone.
        "options": {
            "metric_formatting": {
                "prefix": "$",                # rendered before the value
                "suffix": "/yr",              # rendered after the value
                "decimals": 0,                # round to this many decimal places
                "thousands_separator": True,  # insert "," every 3 digits
                "abbreviate": False,          # True → "184K" instead of "184,250"
            },
            # Other option fields are unused for metric:
            "legend": None,
            "bar_max_width": None,
            "pie_donut_ratio": None,
        },
        "tags": ["licensing", "kpi", "cost"],
    }


def main() -> int:
    setup_logging()
    validate_credentials(logger)
    access_key, secret_key, endpoint = get_credentials()

    sdk = InfinoSDK(access_key, secret_key, endpoint)
    logger.info("Connected to %s", endpoint)

    specs = [
        ("bar",    fine_tuned_bar(DEMO_DATASET)),
        ("donut",  fine_tuned_donut(DEMO_DATASET, DEMO_MAPPING_DATASET)),
        ("metric", fine_tuned_metric(DEMO_DATASET)),
    ]

    for label, spec in specs:
        try:
            viz = sdk.create_visualization(spec)
        except InfinoError as e:
            logger.error("Failed to create %s viz: %s", label, e.message)
            return 1
        logger.info("Created %s viz '%s' (id=%s)", label, viz["attributes"]["title"], viz["id"])

    # Execute the bar viz and dump the resulting ECharts spec so the effect
    # of `mapping`, `legend`, and `bar_max_width` is visible in the output.
    bar_viz = sdk.create_visualization(specs[0][1])
    data = sdk.execute_visualization(bar_viz["id"])
    spec = sdk.to_echarts_option(bar_viz["attributes"], data)
    logger.info("ECharts spec for the bar viz (truncated):")
    print(json.dumps(spec["option"], indent=2)[:1500])

    return 0


if __name__ == "__main__":
    sys.exit(main())
