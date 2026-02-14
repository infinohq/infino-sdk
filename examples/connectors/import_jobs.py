"""
Infino SDK - Import Jobs Example

This example demonstrates the import job lifecycle for syncing data from
external sources into Infino datasets:
- Creating import jobs (create_import_job) for Elasticsearch and SQL sources
- Listing import jobs (get_import_jobs)
- Monitoring job status (polling)
- Deleting import jobs (delete_import_job)

Usage:
    export INFINO_ACCESS_KEY="your_key"
    export INFINO_SECRET_KEY="your_secret"
    export INFINO_ENDPOINT="https://api.infino.ws"
    # Set SOURCE_CONNECTION_ID and optionally TARGET_DATASET
    python examples/connectors/import_jobs.py
"""

import json
import logging
import os

from infino_sdk import InfinoError, InfinoSDK

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

SOURCE_CONNECTION_ID = os.getenv("IMPORT_SOURCE_CONNECTION_ID", "your_connection_id")
TARGET_DATASET = os.getenv("IMPORT_TARGET_DATASET", "imported_data")


# =============================================================================
# IMPORT JOB CONFIGS
# =============================================================================

def elasticsearch_import_config(source_id: str, target_dataset: str) -> dict:
    """Config for importing from Elasticsearch (QueryDSL query)."""
    query = json.dumps({"query": {"match_all": {}}, "size": 1000})
    return {
        "source_id": source_id,
        "target_dataset": target_dataset,
        "query": query,
        "schedule": "0 0 * * *",  # Daily at midnight (cron)
    }


def sql_import_config(source_id: str, target_dataset: str) -> dict:
    """Config for importing from Snowflake/BigQuery (SQL query)."""
    return {
        "source_id": source_id,
        "target_dataset": target_dataset,
        "query": "SELECT * FROM sales_data LIMIT 1000",
        "schedule": "0 */6 * * *",  # Every 6 hours
    }


# =============================================================================
# MAIN
# =============================================================================


def main():
    """Run import jobs demo."""
    access_key = os.getenv("INFINO_ACCESS_KEY", "your_access_key")
    secret_key = os.getenv("INFINO_SECRET_KEY", "your_secret_key")
    endpoint = os.getenv("INFINO_ENDPOINT", "https://api.infino.ws")

    sdk = InfinoSDK(access_key, secret_key, endpoint)
    created_job_ids = []

    try:
        # ---------------------------------------------------------------------
        # Step 1: List existing import jobs
        # ---------------------------------------------------------------------
        logger.info("[STEP 1] Listing existing import jobs...")
        try:
            jobs = sdk.get_import_jobs()
            logger.info("Existing jobs: %d", len(jobs))
            for job in jobs:
                logger.info(
                    "  job_id=%s source_id=%s target=%s status=%s",
                    job.get("job_id"),
                    job.get("source_id"),
                    job.get("target_dataset"),
                    job.get("status"),
                )
        except InfinoError as e:
            logger.warning("Could not list jobs: %s", e.message)

        # ---------------------------------------------------------------------
        # Step 2: Create import job (Elasticsearch example)
        # ---------------------------------------------------------------------
        logger.info("[STEP 2] Creating import job (elasticsearch -> %s)...", TARGET_DATASET)
        try:
            config = elasticsearch_import_config(SOURCE_CONNECTION_ID, TARGET_DATASET)
            result = sdk.create_import_job("elasticsearch", config)
            job_id = result.get("job_id") or result.get("id")
            if job_id:
                created_job_ids.append(("elasticsearch", job_id))
                logger.info("  Created job: %s", job_id)
            else:
                logger.warning("  Response: %s", result)
        except InfinoError as e:
            logger.warning("  Could not create elasticsearch import job: %s", e.message)

        # ---------------------------------------------------------------------
        # Step 3: Create import job (SQL example)
        # ---------------------------------------------------------------------
        logger.info("[STEP 3] Creating import job (snowflake/bigquery -> %s)...", TARGET_DATASET + "_sql")
        try:
            config = sql_import_config(SOURCE_CONNECTION_ID, TARGET_DATASET + "_sql")
            result = sdk.create_import_job("snowflake", config)
            job_id = result.get("job_id") or result.get("id")
            if job_id:
                created_job_ids.append(("snowflake", job_id))
                logger.info("  Created job: %s", job_id)
            else:
                logger.warning("  Response: %s", result)
        except InfinoError as e:
            logger.warning("  Could not create SQL import job: %s", e.message)

        # ---------------------------------------------------------------------
        # Step 4: List jobs again and show status
        # ---------------------------------------------------------------------
        logger.info("[STEP 4] Listing import jobs after create...")
        try:
            jobs = sdk.get_import_jobs()
            for job in jobs:
                logger.info(
                    "  job_id=%s status=%s schedule=%s",
                    job.get("job_id"),
                    job.get("status"),
                    job.get("schedule"),
                )
        except InfinoError as e:
            logger.warning("Could not list jobs: %s", e.message)

        # ---------------------------------------------------------------------
        # Step 5: Poll for job status (if we have a run_id from a one-off run)
        # Import jobs are typically scheduled; polling pattern shown for reference
        # ---------------------------------------------------------------------
        logger.info("[STEP 5] Import jobs are usually scheduled; use get_import_jobs() to monitor.")

        logger.info("Import jobs demo completed.")

    except InfinoError as e:
        logger.error("Infino error: %s", e.message)
        raise
    finally:
        # ---------------------------------------------------------------------
        # Cleanup: delete created import jobs
        # ---------------------------------------------------------------------
        for source_type, job_id in created_job_ids:
            try:
                sdk.delete_import_job(job_id)
                logger.info("Deleted import job: %s (%s)", job_id, source_type)
            except InfinoError as e:
                logger.warning("Could not delete job %s: %s", job_id, e.message)
        sdk.close()


if __name__ == "__main__":
    main()
