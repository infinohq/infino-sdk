"""
Tests for connector operations: query_remote_source_sql, web_search,
get_all_datasets, get_connector_job_status, upload_file
"""

import json
import os
import tempfile
from unittest.mock import Mock, patch

import pytest

from infino_sdk.lib import InfinoError, InfinoSDK


@pytest.mark.unit
def test_query_remote_source_sql(sdk_with_mock_session, mock_response):
    """Test SQL query against a remote source connection"""
    sdk = sdk_with_mock_session

    sql_response = {
        "columns": [
            {"name": "id", "type": "integer"},
            {"name": "name", "type": "text"},
        ],
        "rows": [[1, "Alice"], [2, "Bob"]],
        "total": 2,
    }
    response = mock_response(200, sql_response)
    sdk.session.request.return_value = response

    result = sdk.query_remote_source_sql("conn-123", "SELECT id, name FROM users")

    assert result["total"] == 2
    assert len(result["rows"]) == 2
    call_args = sdk.session.request.call_args
    assert call_args.kwargs["method"] == "POST"
    assert "/source/conn-123/sql" in call_args.kwargs["url"]
    body = json.loads(call_args.kwargs["data"])
    assert body["query"] == "SELECT id, name FROM users"


@pytest.mark.unit
def test_web_search(sdk_with_mock_session, mock_response):
    """Test web search through a web-type connector"""
    sdk = sdk_with_mock_session

    search_response = {
        "results": [
            {"title": "Result 1", "url": "https://example.com/1", "snippet": "..."},
            {"title": "Result 2", "url": "https://example.com/2", "snippet": "..."},
        ]
    }
    response = mock_response(200, search_response)
    sdk.session.request.return_value = response

    result = sdk.web_search("web-conn-1", "infino analytics", max_results=5)

    assert "results" in result
    assert len(result["results"]) == 2
    call_args = sdk.session.request.call_args
    assert call_args.kwargs["method"] == "POST"
    assert "/source/web-conn-1/web" in call_args.kwargs["url"]
    body = json.loads(call_args.kwargs["data"])
    assert body["search_query"] == "infino analytics"
    assert body["max_results"] == 5


@pytest.mark.unit
def test_get_all_datasets_returns_list(sdk_with_mock_session, mock_response):
    """Test get_all_datasets when response is a list"""
    sdk = sdk_with_mock_session

    datasets_response = [
        {"name": "customers", "row_count": 1000},
        {"name": "orders", "row_count": 5000},
    ]
    response = mock_response(200, datasets_response)
    sdk.session.request.return_value = response

    result = sdk.get_all_datasets("conn-456")

    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["name"] == "customers"


@pytest.mark.unit
def test_get_connector_job_status(sdk_with_mock_session, mock_response):
    """Test getting import job status by ID"""
    sdk = sdk_with_mock_session

    job_response = {
        "job_id": "job-789",
        "status": "running",
        "progress": 0.75,
        "records_ingested": 7500,
    }
    response = mock_response(200, job_response)
    sdk.session.request.return_value = response

    result = sdk.get_connector_job_status("job-789")

    assert result["job_id"] == "job-789"
    assert result["status"] == "running"
    assert result["progress"] == 0.75
    call_args = sdk.session.request.call_args
    assert call_args.kwargs["url"].endswith("/import/jobs/job-789")


@pytest.mark.unit
def test_upload_file(sdk_with_mock_session, mock_response):
    """Test multipart file upload for ingestion"""
    sdk = sdk_with_mock_session

    upload_response = {"job_id": "file-upload-001", "status": "completed"}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp:
        tmp.write("name,value\nAlice,100\nBob,200\n")
        tmp_path = tmp.name

    try:
        with patch.object(
            sdk, "request_multipart", return_value=upload_response
        ) as mock_mp:
            result = sdk.upload_file("my-dataset", tmp_path, format="csv")

            assert result["job_id"] == "file-upload-001"
            call_args = mock_mp.call_args
            assert call_args[0][0] == "POST"
            assert "/import/file" in call_args[0][1]
            assert call_args[0][3]["index_name"] == "my-dataset"
            assert call_args[0][3]["format"] == "csv"
    finally:
        os.unlink(tmp_path)


@pytest.mark.unit
def test_upload_file_async(sdk_with_mock_session, mock_response):
    """Test async multipart file upload returns run_id"""
    sdk = sdk_with_mock_session

    upload_response = {"run_id": "file-upload-002", "status": "submitted"}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        tmp.write('[{"key": "val"}]')
        tmp_path = tmp.name

    try:
        with patch.object(
            sdk, "request_multipart", return_value=upload_response
        ) as mock_mp:
            result = sdk.upload_file("my-dataset", tmp_path, async_mode=True)

            assert result["status"] == "submitted"
            assert result["run_id"] == "file-upload-002"
            call_args = mock_mp.call_args
            assert call_args[0][4] == {"async": "true"}
    finally:
        os.unlink(tmp_path)
