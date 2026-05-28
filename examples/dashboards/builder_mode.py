"""
Builder-mode demo: create a dashboard without writing SQL.

The Quickstart in ``docs/dashboards.md`` uses ``source.sql.raw_query`` to
hand-author each query. This example covers the same shape using **Builder
mode** — set ``mapping.x`` and either ``aggregation_type`` (shorthand) or
``source.sql.metrics[0]`` (explicit) and let the gateway generate the SQL.
``mapping.y`` is left empty for aggregating chart types; the metric column
lives in ``metrics[].column`` (Tranche 2).

Also demos the ``filters=`` kwarg added in 0.6.0:
- ``execute_visualization(viz_id, filters=[...])`` — runtime filter chips
- ``execute_dashboard(dash_id, filters=[...])`` — apply to every panel

The example targets the same FlexLM license dataset as ``create_and_render.py``
so you can A/B the two approaches against identical data. Set
``INFINO_DEMO_DATASET`` to point at your own index.

Usage:
    export INFINO_ACCESS_KEY='your_key'
    export INFINO_SECRET_KEY='your_secret'
    export INFINO_ENDPOINT='https://api.infino.ws'
    python -m examples.dashboards.builder_mode
"""

from __future__ import annotations

import json
import os
import sys

from infino_sdk import InfinoSDK


def main() -> int:
    sdk = InfinoSDK(
        access_key=os.environ["INFINO_ACCESS_KEY"],
        secret_key=os.environ["INFINO_SECRET_KEY"],
        endpoint=os.environ.get("INFINO_ENDPOINT", "https://api.infino.ws"),
    )

    index = os.environ.get("INFINO_DEMO_DATASET", "flexlm_cdslmd.rel")
    print(f"→ using dataset {index!r}")

    # ─── 1. Raw-SQL viz (for comparison) ───────────────────────────────────
    raw_viz = sdk.create_visualization({
        "title": "Denials per feature (raw SQL)",
        "source": {
            "kind": "sql",
            "index": index,
            "sql": {
                "raw_query": (
                    f"SELECT feature_name, COUNT(*) AS denials "
                    f"FROM `{index}` "
                    f"WHERE event_type = 'DENIED' "
                    f"GROUP BY feature_name ORDER BY denials DESC LIMIT 10"
                ),
            },
        },
        "chart": {"type": "bar"},
        # Raw-SQL mode: mapping.y lists response columns the renderer
        # should bind to the chart's y-axis. The gateway uses the
        # raw_query verbatim; mapping fields drive `metadata.binding`.
        "mapping": {"x": {"column": "feature_name"}, "y": ["denials"], "series": None},
    })
    print(f"✓ raw-SQL viz   {raw_viz['id']}")

    # ─── 2. Builder-mode viz — same shape, no raw_query ────────────────────
    # The gateway picks the aggregation, GROUP BY, ORDER BY, LIMIT, and
    # dialect-aware quoting based on the mapping + aggregation_type.
    builder_viz = sdk.create_visualization({
        "title": "Denials per feature (Builder mode)",
        "source": {
            "kind": "sql",
            "index": index,
            "sql": {"limit": 10},
            # NOTE: no raw_query → triggers server-side SQL generation
        },
        "chart": {"type": "bar"},
        # Builder mode for an aggregating chart: leave mapping.y empty —
        # the gateway derives the y-axis column + alias from
        # `source.sql.metrics[0]` (or `aggregation_type` shorthand below).
        "mapping": {"x": {"column": "feature_name"}, "y": [], "series": None},
        "aggregation_type": "count",
        # Saved filters travel with the viz and apply at every execute call:
        "filters": [
            {"field": "event_type", "operator": "is", "value": "DENIED"},
            # 'id', 'enabled', etc. auto-filled by the SDK
        ],
    })
    print(f"✓ builder viz   {builder_viz['id']}")

    # ─── 3. Execute both and compare ────────────────────────────────────────
    raw_data = sdk.execute_visualization(raw_viz["id"])
    builder_data = sdk.execute_visualization(builder_viz["id"])
    print(f"\nraw rows     = {len(raw_data['rows'])}")
    print(f"builder rows = {len(builder_data['rows'])}")
    print(f"builder executed_query:\n  {builder_data['metadata']['executed_query']}")

    # ─── 4. Apply a runtime filter via `filters=` kwarg ─────────────────────
    filtered = sdk.execute_visualization(
        builder_viz["id"],
        filters=[
            {"field": "feature_name", "operator": "is_one_of",
             "value": ["AMS_Designer", "Spectre_Simulator", "Genus_Synthesis"]},
        ],
    )
    print(f"\nruntime-filtered rows = {len(filtered['rows'])}")
    print(f"filters_applied = {filtered['metadata'].get('filters_applied')}")
    print(f"filters_skipped = {filtered['metadata'].get('filters_skipped')}")

    # ─── 4b. Apply a runtime time window via `time_range=` kwarg ───────────
    # Gateway rewrites this into an is_between filter on the viz's time
    # column (source.sql.time_column, default @timestamp).
    windowed = sdk.execute_visualization(
        builder_viz["id"],
        time_range={"from": "2026-04-01T00:00:00Z",
                    "to":   "2026-05-01T00:00:00Z"},
    )
    print(f"\ntime-windowed rows = {len(windowed['rows'])}")
    print(f"filters_applied    = {windowed['metadata'].get('filters_applied')}")

    # ─── 5. Bundle into a dashboard and apply a dashboard-wide filter ───────
    dash = sdk.create_dashboard({
        "title": "Builder-mode demo",
        "panels": [
            {"viz_id": raw_viz["id"]},
            {"viz_id": builder_viz["id"]},
        ],
    })
    print(f"\n✓ dashboard {dash['id']}")

    # `filters=` on execute_dashboard applies to every panel.
    panels = sdk.execute_dashboard(
        dash["id"],
        filters=[
            {"field": "feature_name", "operator": "is_not", "value": "AMS_Designer"},
        ],
    )
    print("\nper-panel results:")
    for p in panels:
        if p.get("error"):
            print(f"  ✗ panel {p['id']}: {p['error']}")
            continue
        title = (p.get("viz") or {}).get("title", "?")
        rows = (p.get("data") or {}).get("rows") or []
        meta = (p.get("data") or {}).get("metadata") or {}
        applied = meta.get("filters_applied", [])
        print(f"  ✓ {title!r}  rows={len(rows)}  applied={applied}")

    # Cleanup-friendly: print ids so you can delete this run.
    print(f"\nto clean up:")
    print(f"  sdk.delete_dashboard({dash['id']!r})")
    print(f"  sdk.delete_visualization({raw_viz['id']!r})")
    print(f"  sdk.delete_visualization({builder_viz['id']!r})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
