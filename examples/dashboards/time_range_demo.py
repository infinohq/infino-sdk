"""Time-range injection demo.

Demonstrates the `time_range=` kwarg added in SDK 0.6.0. Requires:
  - INFINO_ACCESS_KEY / INFINO_SECRET_KEY env vars
  - INFINO_ENDPOINT (defaults to https://api.infino.ws)
  - INFINO_DEMO_VIZ_ID — id of a saved SQL viz with a time column (defaults
    to @timestamp; set source.sql.time_column on the viz spec if different)

Usage:
    export INFINO_ACCESS_KEY=...
    export INFINO_SECRET_KEY=...
    export INFINO_DEMO_VIZ_ID=...
    python -m examples.dashboards.time_range_demo
"""
import os
import sys

from infino_sdk import InfinoSDK


def main() -> int:
    sdk = InfinoSDK(
        access_key=os.environ["INFINO_ACCESS_KEY"],
        secret_key=os.environ["INFINO_SECRET_KEY"],
        endpoint=os.environ.get("INFINO_ENDPOINT", "https://api.infino.ws"),
    )
    viz_id = os.environ["INFINO_DEMO_VIZ_ID"]

    # Baseline — no time filter
    baseline = sdk.execute_visualization(viz_id)
    print(f"baseline rows: {len(baseline['rows'])}")

    # Last 30 days
    last_30 = sdk.execute_visualization(viz_id, time_range={
        "from": "2026-04-22T00:00:00Z",
        "to":   "2026-05-22T00:00:00Z",
    })
    print(f"last 30 days: {len(last_30['rows'])} rows")
    print(f"filters_applied: {last_30['metadata'].get('filters_applied')}")
    print(f"executed_query: {last_30['metadata']['executed_query'][:200]}")

    # Combined with a feature filter
    combined = sdk.execute_visualization(
        viz_id,
        filters=[{"field": "event_type", "operator": "is", "value": "DENIED"}],
        time_range={"from": "2026-04-22T00:00:00Z", "to": "2026-05-22T00:00:00Z"},
    )
    print(f"combined: {len(combined['rows'])} rows, applied={combined['metadata'].get('filters_applied')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
