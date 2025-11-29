"""
Unit tests for PromQL query operations

Based on patterns from infino/tests/api/python/src/utils/performance.py
"""

import json
import time
from unittest.mock import MagicMock, Mock, patch

import pytest

from infino_sdk import InfinoError, InfinoSDK


class TestPromQLInstantQueries:
    """Test PromQL instant queries"""

    def test_simple_instant_query(self, mock_sdk):
        """Test simple PromQL instant query"""
        sdk, mock_requests = mock_sdk

        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"__name__": "cpu_usage", "host": "server1"},
                        "value": [time.time(), "75.5"],
                    }
                ],
            },
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query
        result = sdk.query_dataset_in_promql(
            'cpu_usage{host="server1"}', "test_dataset.aly"
        )

        # Verify
        assert result["status"] == "success"
        assert result["data"]["resultType"] == "vector"
        assert len(result["data"]["result"]) == 1

    def test_instant_query_with_aggregation(self, mock_sdk):
        """Test PromQL instant query with aggregation"""
        sdk, mock_requests = mock_sdk

        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{"metric": {}, "value": [time.time(), "60.4"]}],
            },
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query
        result = sdk.prom_ql_query("avg(cpu_usage)", "test_index.aly")

        # Verify
        assert result["status"] == "success"
        assert result["data"]["resultType"] == "vector"

    def test_instant_query_by_label(self, mock_sdk):
        """Test PromQL instant query with aggregation by label"""
        sdk, mock_requests = mock_sdk

        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {"metric": {"host": "server1"}, "value": [time.time(), "77.5"]},
                    {"metric": {"host": "server2"}, "value": [time.time(), "45.3"]},
                ],
            },
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query
        result = sdk.prom_ql_query("avg(cpu_usage) by (host)", "test_index.aly")

        # Verify
        assert result["status"] == "success"
        assert len(result["data"]["result"]) == 2


class TestPromQLRangeQueries:
    """Test PromQL range queries"""

    def test_basic_range_query(self, mock_sdk):
        """Test basic PromQL range query"""
        sdk, mock_requests = mock_sdk

        # Mock response
        now = int(time.time() * 1000)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [
                    {
                        "metric": {"__name__": "cpu_usage", "host": "server1"},
                        "values": [
                            [now / 1000, "75.5"],
                            [(now + 60000) / 1000, "80.1"],
                        ],
                    }
                ],
            },
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query
        start_time = now - 60000
        end_time = now + 120000
        step = 60

        result = sdk.query_dataset_in_promql_range(
            'cpu_usage{host="server1"}', start_time, end_time, step, "test_dataset.aly"
        )

        # Verify
        assert result["status"] == "success"
        assert result["data"]["resultType"] == "matrix"
        assert len(result["data"]["result"]) == 1
        assert len(result["data"]["result"][0]["values"]) == 2

    def test_range_query_with_rate(self, mock_sdk):
        """Test PromQL range query with rate function"""
        sdk, mock_requests = mock_sdk

        # Mock response
        now = int(time.time() * 1000)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [
                    {
                        "metric": {"__name__": "cpu_usage", "host": "server1"},
                        "values": [
                            [now / 1000, "0.05"],
                            [(now + 60000) / 1000, "0.06"],
                        ],
                    }
                ],
            },
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query
        start_time = now - 60000
        end_time = now + 300000
        step = 60

        result = sdk.prom_ql_query_range(
            "rate(cpu_usage[5m])", start_time, end_time, step, "test_index.aly"
        )

        # Verify
        assert result["status"] == "success"
        assert result["data"]["resultType"] == "matrix"

    def test_range_query_multiple_series(self, mock_sdk):
        """Test PromQL range query returning multiple time series"""
        sdk, mock_requests = mock_sdk

        # Mock response
        now = int(time.time() * 1000)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [
                    {
                        "metric": {"host": "server1"},
                        "values": [
                            [now / 1000, "75.5"],
                            [(now + 60000) / 1000, "80.1"],
                        ],
                    },
                    {
                        "metric": {"host": "server2"},
                        "values": [
                            [now / 1000, "45.3"],
                            [(now + 60000) / 1000, "48.7"],
                        ],
                    },
                ],
            },
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query
        start_time = now - 60000
        end_time = now + 120000
        step = 60

        result = sdk.prom_ql_query_range(
            "avg(cpu_usage) by (host)", start_time, end_time, step, "test_index.aly"
        )

        # Verify
        assert result["status"] == "success"
        assert result["data"]["resultType"] == "matrix"
        assert len(result["data"]["result"]) == 2


class TestPromQLLabelSelectors:
    """Test PromQL label selector queries"""

    def test_equality_selector(self, mock_sdk):
        """Test PromQL query with equality label selector"""
        sdk, mock_requests = mock_sdk

        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"__name__": "cpu_usage", "env": "production"},
                        "value": [time.time(), "75.5"],
                    }
                ],
            },
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query
        result = sdk.prom_ql_query('cpu_usage{env="production"}', "test_index.aly")

        # Verify
        assert result["status"] == "success"
        assert result["data"]["result"][0]["metric"]["env"] == "production"

    def test_regex_selector(self, mock_sdk):
        """Test PromQL query with regex label selector"""
        sdk, mock_requests = mock_sdk

        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"__name__": "cpu_usage", "region": "us-east"},
                        "value": [time.time(), "75.5"],
                    },
                    {
                        "metric": {"__name__": "cpu_usage", "region": "us-west"},
                        "value": [time.time(), "45.3"],
                    },
                ],
            },
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query
        result = sdk.prom_ql_query('cpu_usage{region=~"us-.*"}', "test_index.aly")

        # Verify
        assert result["status"] == "success"
        assert len(result["data"]["result"]) == 2

    def test_multiple_label_selectors(self, mock_sdk):
        """Test PromQL query with multiple label selectors"""
        sdk, mock_requests = mock_sdk

        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {
                            "__name__": "cpu_usage",
                            "env": "production",
                            "region": "us-east",
                        },
                        "value": [time.time(), "75.5"],
                    }
                ],
            },
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query
        result = sdk.prom_ql_query(
            'cpu_usage{env="production",region="us-east"}', "test_index.aly"
        )

        # Verify
        assert result["status"] == "success"
        assert result["data"]["result"][0]["metric"]["env"] == "production"
        assert result["data"]["result"][0]["metric"]["region"] == "us-east"


class TestPromQLArithmeticOperations:
    """Test PromQL arithmetic operations"""

    def test_multiplication(self, mock_sdk):
        """Test PromQL query with multiplication"""
        sdk, mock_requests = mock_sdk

        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"__name__": "cpu_usage", "host": "server1"},
                        "value": [time.time(), "151.0"],
                    }
                ],
            },
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query
        result = sdk.prom_ql_query('cpu_usage{host="server1"} * 2', "test_index.aly")

        # Verify
        assert result["status"] == "success"
        assert float(result["data"]["result"][0]["value"][1]) == 151.0

    def test_addition(self, mock_sdk):
        """Test PromQL query with addition"""
        sdk, mock_requests = mock_sdk

        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{"metric": {}, "value": [time.time(), "100.0"]}],
            },
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query
        result = sdk.prom_ql_query("cpu_usage + memory_usage", "test_index.aly")

        # Verify
        assert result["status"] == "success"


class TestPromQLErrorHandling:
    """Test PromQL error handling"""

    def test_invalid_query_syntax(self, mock_sdk):
        """Test handling of invalid PromQL syntax"""
        sdk, mock_requests = mock_sdk

        # Mock error response
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "status": "error",
            "errorType": "bad_data",
            "error": "parse error: unexpected end of input",
        }
        mock_response.raise_for_status.side_effect = Exception("Bad Request")
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query and expect error
        with pytest.raises(Exception):
            sdk.query_dataset_in_promql("cpu_usage{", "test_dataset.aly")

    def test_query_timeout(self, mock_sdk):
        """Test handling of query timeout"""
        sdk, mock_requests = mock_sdk

        # Mock timeout response
        mock_response = Mock()
        mock_response.status_code = 504
        mock_response.json.return_value = {
            "status": "error",
            "errorType": "timeout",
            "error": "query timeout",
        }
        mock_response.raise_for_status.side_effect = Exception("Gateway Timeout")
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query and expect error
        with pytest.raises(Exception):
            sdk.query_dataset_in_promql("rate(cpu_usage[1h])", "test_dataset.aly")

    def test_dataset_not_found(self, mock_sdk):
        """Test handling of non-existent dataset"""
        sdk, mock_requests = mock_sdk

        # Mock error response
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"error": "index_not_found_exception"}
        mock_response.raise_for_status.side_effect = Exception("Not Found")
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query and expect error
        with pytest.raises(Exception):
            sdk.query_dataset_in_promql("cpu_usage", "nonexistent.aly")
