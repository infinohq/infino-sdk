"""
End-to-end: create SQL-backed visualizations, bundle them into a
dashboard, execute every panel in parallel, and render the whole
dashboard as one composite HTML page that honors each panel's stored
``layout: {x, y, w, h}`` via CSS Grid.

The example SQL targets a license-management dataset:
    flexlm_cdslmd.rel              FlexLM license-server events
    cdn_product_feature_mapping.rel feature → product / stage mapping

This shape was chosen because the resulting dashboard covers a JOIN-
based query, a heatmap, a metric card, a horizontal bar, and a pie in
one flow — exercising more of the renderer than a single-table demo
would. Point ``INFINO_DEMO_DATASET`` at one of your own datasets and
swap the SQL to match your schema.

Currently supports ``source.kind == "sql"`` with a non-empty
``raw_query``. Runtime filter / time-range overrides are not yet wired
through; bake them into the SQL string until then.

Usage:
    export INFINO_ACCESS_KEY='your_key'
    export INFINO_SECRET_KEY='your_secret'
    export INFINO_ENDPOINT='https://api.infino.ws'
    pip install pyecharts                  # optional, only for HTML render
    python -m examples.dashboards.create_and_render
"""

from __future__ import annotations

import sys

from infino_sdk import InfinoError, InfinoSDK

from .common import (
    DEMO_DATASET,
    DEMO_MAPPING_DATASET,
    build_dashboard_html,
    get_credentials,
    get_logger,
    setup_logging,
    validate_credentials,
)

logger = get_logger(__name__)


def _flexlm_viz_specs(dataset: str, mapping_dataset: str) -> list[dict]:
    """
    Five panels modelled on a real FlexLM license-management dashboard.

    Each spec is intentionally minimal: ``title``, ``source``, ``chart`` —
    the server fills mapping / options / tags / limit / etc. The internal
    ``_layout_hint`` is popped before the spec is sent and used when
    composing the dashboard.
    """
    return [
        # 1. Single-value KPI — total denials in the window.
        {
            "title": "Total License Denials",
            "source": {
                "kind": "sql",
                "index": dataset,
                "sql": {
                    "raw_query": (
                        f"SELECT COUNT(*) AS `Denials` "
                        f"FROM `{dataset}` "
                        f"WHERE `event_type` = 'DENIED'"
                    ),
                },
            },
            "chart": {"type": "metric"},
            "visualization_mode": "table",
            "_layout_hint": {"x": 0, "y": 0, "w": 12, "h": 8},
        },
        # 2. Top denied features — vertical bar.
        {
            "title": "Top Denied Features",
            "source": {
                "kind": "sql",
                "index": dataset,
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
                },
            },
            "chart": {"type": "bar"},
            "_layout_hint": {"x": 12, "y": 0, "w": 18, "h": 16},
        },
        # 3. Denials by primary stage — pie. Joins the feature-mapping
        #    table to roll up raw feature names into design-flow stages.
        {
            "title": "Denials by Stage",
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
            "_layout_hint": {"x": 30, "y": 0, "w": 18, "h": 16},
        },
        # 4. Denials heatmap — feature x hour of day.
        {
            "title": "License Denials — Feature x Hour of Day",
            "source": {
                "kind": "sql",
                "index": dataset,
                "sql": {
                    "raw_query": (
                        f"SELECT "
                        f"EXTRACT(HOUR FROM `@timestamp`) AS `Hour of day (UTC)`, "
                        f"`feature_name` AS `Feature`, "
                        f"COUNT(*) AS `Denials` "
                        f"FROM `{dataset}` "
                        f"WHERE `event_type` = 'DENIED' "
                        f"GROUP BY EXTRACT(HOUR FROM `@timestamp`), `feature_name` "
                        f"ORDER BY `Hour of day (UTC)`, `Feature` "
                        f"LIMIT 200"
                    ),
                },
            },
            "chart": {"type": "heatmap"},
            "mapping": {
                "x": "Hour of day (UTC)",
                "y": ["Denials"],
                "series_split_by": "Feature",
            },
            "_layout_hint": {"x": 0, "y": 16, "w": 30, "h": 18},
        },
        # 5. Shelfware analysis — least-used (lowest checkout count)
        #    features. Horizontal bar so the long feature names stay
        #    readable.
        {
            "title": "Shelfware Cost — Lowest-Utilization Features",
            "source": {
                "kind": "sql",
                "index": dataset,
                "sql": {
                    "raw_query": (
                        f"SELECT `feature_name` AS `Feature`, "
                        f"COUNT(*) AS `Checkouts` "
                        f"FROM `{dataset}` "
                        f"WHERE `event_type` = 'OUT' "
                        f"GROUP BY `feature_name` "
                        f"ORDER BY `Checkouts` ASC "
                        f"LIMIT 10"
                    ),
                },
            },
            "chart": {"type": "horizontalBar"},
            "_layout_hint": {"x": 30, "y": 16, "w": 18, "h": 18},
        },
    ]


def main() -> int:
    setup_logging()
    validate_credentials(logger)
    access_key, secret_key, endpoint = get_credentials()

    sdk = InfinoSDK(access_key, secret_key, endpoint)
    logger.info("Connected to %s", endpoint)

    # 1. Create five visualizations. Server fills mapping / options / etc.
    viz_specs = _flexlm_viz_specs(DEMO_DATASET, DEMO_MAPPING_DATASET)
    viz_ids: list[str] = []
    layouts: list[dict] = []

    for spec in viz_specs:
        layout = spec.pop("_layout_hint")
        try:
            viz = sdk.create_visualization(spec)
        except InfinoError as e:
            logger.error("Failed to create visualization '%s': %s", spec["title"], e.message)
            return 1
        viz_ids.append(viz["id"])
        layouts.append(layout)
        logger.info("Created visualization '%s' (id=%s)", viz["attributes"]["title"], viz["id"])

    # 2. Bundle them into a dashboard with explicit per-panel layouts.
    #    Omit `layout` and the server auto-flows panels into a 2-column grid.
    try:
        dashboard = sdk.create_dashboard(
            {
                "title": "FlexLM License Overview",
                "panels": [
                    {"viz_id": vid, "layout": layout}
                    for vid, layout in zip(viz_ids, layouts)
                ],
            }
        )
    except InfinoError as e:
        logger.error("Failed to create dashboard: %s", e.message)
        return 1

    logger.info(
        "Created dashboard '%s' (id=%s) with %d panels",
        dashboard["attributes"]["title"],
        dashboard["id"],
        len(dashboard["attributes"]["panels"]),
    )

    # 3. Render a layout-aware composite HTML page from the stored dashboard.
    try:
        import pyecharts  # noqa: F401
    except ImportError:
        logger.warning(
            "pyecharts not installed — skipping HTML render. "
            "Install with `pip install pyecharts` to produce dashboard.html."
        )
        return 0

    html_out = build_dashboard_html(sdk, dashboard["id"])
    out_path = "dashboard.html"
    with open(out_path, "w") as f:
        f.write(html_out)
    logger.info("Rendered layout-aware dashboard → %s", out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
