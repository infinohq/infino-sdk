#!/usr/bin/env python3
"""
Example: File Upload to Infino

This example demonstrates how to upload files (JSON, JSONL, CSV) to Infino
using both synchronous and asynchronous modes.

Usage:
    # Set environment variables
    export INFINO_ACCESS_KEY="your_access_key"
    export INFINO_SECRET_KEY="your_secret_key"
    export INFINO_ENDPOINT="https://api.infino.ws"

    # Run the example
    python file_upload.py

================================================================================
WORKFLOW
================================================================================

Step 1: Initialize SDK
    sdk = InfinoSDK(access_key, secret_key, endpoint)

Step 2: Create dataset (if needed)
    sdk.create_dataset("my_dataset")

Step 3: Upload file (choose sync or async mode)
    # Sync: Waits for completion
    result = sdk.upload_file(dataset, file_path, format="csv", async_mode=False)
    
    # Async: Returns immediately, poll for status
    result = sdk.upload_file(dataset, file_path, format="auto", async_mode=True)
    status = sdk.get_connector_job_status(result['run_id'])

================================================================================
RESPONSE: sdk.upload_file() with async_mode=False (Synchronous)
================================================================================

Waits for the file to be fully processed before returning.

{
    "connector_id": "file",                    # Connector type identifier
    "run_id": "61ad7a3c-12cb-471e-...",        # Unique job identifier (UUID)
    "status": "completed",                     # Job status: "completed", "failed"
    "message": "File 'example.csv' processed successfully",  # Human-readable message
    "stats": {                                 # Processing statistics
        "documents_processed": 24531,          # Number of documents successfully ingested
        "documents_failed": 0,                 # Number of documents that failed
        "bytes_processed": 12292133,           # Total bytes processed
        "duration_ms": 0,                      # Processing time in milliseconds
        "avg_throughput_docs_per_sec": 9482.1  # Average ingestion rate
    },
    "errors": []                               # List of error messages (if any)
}

================================================================================
RESPONSE: sdk.upload_file() with async_mode=True (Asynchronous)
================================================================================

Returns immediately after submitting the job. Use run_id to poll for status.

{
    "connector_id": "file",                    # Connector type identifier
    "run_id": "7fd9eb57-ab4f-4c2a-...",        # Unique job identifier (use for polling)
    "status": "submitted",                     # Initial status: "submitted"
    "message": "File 'example.csv' submitted for background processing",
    "stats": null,                             # Stats not available until completed
    "errors": []                               # Empty on successful submission
}

================================================================================
RESPONSE: sdk.get_connector_job_status(run_id) - While Running
================================================================================

{
    "run_id": "7fd9eb57-ab4f-4c2a-...",        # Unique job identifier
    "status": "running",                       # "submitted", "running", "completed", "failed"
    "connector_id": "file",                    # Connector type identifier
    "connection_id": null,                     # Connection ID (if applicable)
    "index_name": "my_dataset",                # Target dataset/index name
    "started_at": "2025-12-18T08:08:45.068839626+00:00",   # Job start (ISO 8601)
    "completed_at": "2025-12-18T08:08:45.840483308+00:00", # Job completion (ISO 8601)
    "duration_ms": 771,                        # Processing time in milliseconds
    "error_message": null,                     # Error message (if failed)
    "stats": {                                 # Processing statistics
        "documents_processed": 0,              # Documents processed so far
        "documents_failed": 0,                 # Documents failed so far
        "bytes_processed": 0,                  # Bytes processed so far
        "avg_throughput_docs_per_sec": 0.0,    # Current throughput rate
        "errors": []                           # List of processing errors
    }
}

================================================================================
RESPONSE: sdk.get_connector_job_status(run_id) - When Completed
================================================================================

{
    "run_id": "7fd9eb57-ab4f-4c2a-...",
    "status": "completed",                     # Final status
    "connector_id": "file",
    "connection_id": null,
    "index_name": "my_dataset",
    "started_at": "2025-12-18T08:08:45.068839626+00:00",
    "completed_at": "2025-12-18T08:08:46.500000000+00:00",
    "duration_ms": 1431,
    "error_message": null,
    "stats": {
        "documents_processed": 24531,          # Total documents ingested
        "documents_failed": 0,
        "bytes_processed": 12292133,
        "avg_throughput_docs_per_sec": 9482.1,
        "errors": []
    }
}

================================================================================
STATUS VALUES
================================================================================

Upload status (async_mode=True):
    - "submitted"  : Job received, queued for processing
    
Job status (get_connector_job_status):
    - "submitted"  : Job received, not yet started
    - "running"    : Job is actively processing
    - "completed"  : Job finished successfully
    - "failed"     : Job failed (check error_message and stats.errors)

================================================================================
"""
import json
import os
import sys
import tempfile
import time

from infino_sdk import InfinoError, InfinoSDK


def create_sample_files():
    """Create sample data files for testing."""
    # Sample data
    json_data = [
        {"id": 1, "name": "Alice", "department": "Engineering", "salary": 75000},
        {"id": 2, "name": "Bob", "department": "Sales", "salary": 65000},
        {"id": 3, "name": "Charlie", "department": "Engineering", "salary": 80000},
    ]

    # Create JSON file
    json_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(json_data, json_file)
    json_file.close()

    # Create JSONL file (newline-delimited JSON)
    jsonl_file = tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False)
    for record in json_data:
        jsonl_file.write(json.dumps(record) + '\n')
    jsonl_file.close()

    # Create CSV file
    csv_file = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
    csv_file.write("id,name,department,salary\n")
    for record in json_data:
        csv_file.write(f"{record['id']},{record['name']},{record['department']},{record['salary']}\n")
    csv_file.close()

    return json_file.name, jsonl_file.name, csv_file.name


def sync_upload_example(sdk: InfinoSDK, file_path: str, dataset: str, format: str):
    """Example: Synchronous file upload (waits for completion).
    
    See RESPONSE: sdk.upload_file() with async_mode=False at top of file for response structure.
    """
    print(f"\n{'='*60}")
    print(f"Sync Upload Example - {format.upper()} file")
    print(f"{'='*60}")

    try:
        print(f"Uploading {os.path.basename(file_path)} to dataset '{dataset}'...")

        result = sdk.upload_file(
            dataset=dataset,
            file_path=file_path,
            format=format,
            async_mode=False  # Wait for completion (default)
        )

        print(f"Status: {result['status']}")
        print(f"Message: {result.get('message', 'N/A')}")

        if result.get('stats'):
            stats = result['stats']
            print(f"Documents processed: {stats.get('documents_processed', 'N/A')}")
            print(f"Documents failed: {stats.get('documents_failed', 'N/A')}")
            if stats.get('duration_ms'):
                print(f"Duration: {stats['duration_ms']}ms")
            if stats.get('avg_throughput_docs_per_sec'):
                print(f"Throughput: {stats['avg_throughput_docs_per_sec']:.1f} docs/sec")

        if result.get('errors'):
            print(f"Errors: {result['errors']}")

        return True

    except InfinoError as e:
        print(f"Upload failed: {e.message}")
        if e.status_code():
            print(f"Status code: {e.status_code()}")
        return False


def async_upload_example(sdk: InfinoSDK, file_path: str, dataset: str):
    """Example: Asynchronous file upload with polling.
    
    See response structures at top of file:
    - RESPONSE: sdk.upload_file() with async_mode=True
    - RESPONSE: sdk.get_connector_job_status(run_id) - While Running
    - RESPONSE: sdk.get_connector_job_status(run_id) - When Completed
    """
    print(f"\n{'='*60}")
    print("Async Upload Example - Submit and Poll")
    print(f"{'='*60}")

    try:
        print(f"Submitting {os.path.basename(file_path)} for async processing...")

        # Submit file for async processing
        result = sdk.upload_file(
            dataset=dataset,
            file_path=file_path,
            format="auto",  # Auto-detect format
            async_mode=True  # Return immediately with job ID
        )

        run_id = result['run_id']
        print(f"Job submitted! Run ID: {run_id}")
        print(f"Initial status: {result['status']}")

        # Poll for completion
        print("\nPolling for job completion...")
        max_polls = 30
        poll_interval = 2  # seconds

        for i in range(max_polls):
            status = sdk.get_connector_job_status(run_id)
            current_status = status.get('status', 'unknown')

            print(f"  Poll {i+1}: Status = {current_status}")

            if current_status == 'completed':
                print("\nJob completed successfully!")
                
                if status.get('stats'):
                    stats = status['stats']
                    print(f"Documents processed: {stats.get('documents_processed', 'N/A')}")
                    print(f"Documents failed: {stats.get('documents_failed', 'N/A')}")
                return True

            elif current_status == 'failed':
                print(f"\nJob failed!")
                if status.get('errors'):
                    print(f"Errors: {status['errors']}")
                return False

            time.sleep(poll_interval)

        print("\nTimeout waiting for job completion")
        return False

    except InfinoError as e:
        print(f"Upload failed: {e.message}")
        return False


def main():
    """Main function demonstrating file upload functionality."""
    # Configuration - use environment variables or replace with your credentials
    ACCESS_KEY = os.environ.get("INFINO_ACCESS_KEY", "your_access_key")
    SECRET_KEY = os.environ.get("INFINO_SECRET_KEY", "your_secret_key")
    ENDPOINT = os.environ.get("INFINO_ENDPOINT", "https://api.infino.ws")
    DATASET = "file_test"

    # Check for credentials
    if ACCESS_KEY == "your_access_key":
        print("Please set INFINO_ACCESS_KEY and INFINO_SECRET_KEY environment variables")
        print("Or update the credentials in this script")
        print("\nExample:")
        print("  export INFINO_ACCESS_KEY='your_key'")
        print("  export INFINO_SECRET_KEY='your_secret'")
        print("  export INFINO_ENDPOINT='https://api.infino.ws'")
        sys.exit(1)

    print(f"Connecting to Infino at {ENDPOINT}")
    print(f"Using dataset: {DATASET}")

    # Initialize SDK
    sdk = InfinoSDK(ACCESS_KEY, SECRET_KEY, ENDPOINT)

    try:
        # Create sample data files
        print("\nCreating sample data files...")
        json_file, jsonl_file, csv_file = create_sample_files()
        print(f"  JSON file: {json_file}")
        print(f"  JSONL file: {jsonl_file}")
        print(f"  CSV file: {csv_file}")

        # Create dataset (will succeed even if it already exists)
        print(f"\nCreating dataset '{DATASET}'...")
        try:
            sdk.create_dataset(DATASET)
            print("Dataset created successfully")
        except InfinoError as e:
            if e.status_code() == 409:
                print("Dataset already exists, continuing...")
            else:
                raise

        # Example 1: Sync JSON upload
        sync_upload_example(sdk, json_file, DATASET, "json")

        # Example 2: Sync CSV upload
        sync_upload_example(sdk, csv_file, DATASET, "csv")

        # Example 3: Sync JSONL upload
        sync_upload_example(sdk, jsonl_file, DATASET, "jsonl")

        # Example 4: Async upload with polling
        async_upload_example(sdk, csv_file, DATASET)

        # Cleanup temp files
        print("\nCleaning up temporary files...")
        os.unlink(json_file)
        os.unlink(jsonl_file)
        os.unlink(csv_file)

        print(f"\n{'='*60}")
        print("All examples completed!")
        print(f"{'='*60}")

    except InfinoError as e:
        print(f"\nError: {e.message}")
        if e.status_code():
            print(f"Status code: {e.status_code()}")
        sys.exit(1)

    finally:
        sdk.close()


if __name__ == "__main__":
    main()
