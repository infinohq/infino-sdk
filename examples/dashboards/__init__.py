"""
Infino SDK - Dashboard & Visualization Examples

This package shows how to programmatically build, execute, and render
visualizations and dashboards with the Infino Python SDK.

Examples:
    - create_and_render.py: Create SQL-backed visualizations, bundle them
      into a dashboard, execute every panel in parallel, and render the
      result as a layout-aware composite HTML page.
    - advanced_chart_config.py: Fine-grained chart configuration. Shows
      every visualization option (mapping, legend, bar_max_width,
      pie_donut_ratio, metric_formatting, tags, description) with
      inline comments explaining what each knob does.

The example SQL targets a license-management dataset
(``flexlm_cdslmd.rel`` + ``cdn_product_feature_mapping.rel``) so the
flow exercises a JOIN-based query, a heatmap, a metric card, a
horizontal bar, and a pie in one go. Swap ``INFINO_DEMO_DATASET`` to
point at one of your own datasets.

Common helpers (credentials, logging, HTML render) live in the ``common``
subpackage.
"""
