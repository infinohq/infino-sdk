"""
Unit tests for SQL query operations

Based on patterns from infino/tests/api/python/src/utils/sql.py
"""

import json
from unittest.mock import Mock

import pytest

from infino_sdk import InfinoError, InfinoSDK


class TestBasicSQLQueries:
    """Test basic SQL query operations"""

    def test_simple_select_query(self, mock_sdk):
        """Test simple SELECT query"""
        sdk, mock_requests = mock_sdk

        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "user_id", "type": "keyword"},
                {"name": "action", "type": "keyword"},
                {"name": "timestamp", "type": "date"},
            ],
            "rows": [
                ["user_123", "login", "2024-01-15T10:00:00Z"],
                ["user_456", "logout", "2024-01-15T11:00:00Z"],
            ],
            "total": 2,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        # Execute query
        query = "SELECT user_id, action, timestamp FROM logs.doc LIMIT 10"
        result = sdk.query_dataset_in_sql(query)

        # Verify
        assert result["total"] == 2
        assert len(result["rows"]) == 2
        assert len(result["columns"]) == 3
        sdk.session.request.assert_called_once()

    def test_select_with_where_clause(self, mock_sdk):
        """Test SELECT with WHERE clause"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [{"name": "user_id", "type": "keyword"}],
            "rows": [["user_123"]],
            "total": 1,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = "SELECT user_id FROM logs.doc WHERE action = 'login'"
        result = sdk.query_dataset_in_sql(query)

        assert result["total"] == 1
        assert result["rows"][0][0] == "user_123"

    def test_count_query(self, mock_sdk):
        """Test COUNT aggregation"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [{"name": "count", "type": "long"}],
            "rows": [[1500]],
            "total": 1,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = "SELECT COUNT(*) as count FROM logs.doc"
        result = sdk.query_dataset_in_sql(query)

        assert result["rows"][0][0] == 1500

    def test_sql_query_alias(self, mock_sdk):
        """Test sql_query() method (alias for sql())"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [{"name": "status", "type": "keyword"}],
            "rows": [["success"]],
            "total": 1,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = "SELECT status FROM logs.doc LIMIT 1"
        result = sdk.query_dataset_in_sql(query)

        assert result["rows"][0][0] == "success"


class TestSQLAggregations:
    """Test SQL aggregation functions"""

    def test_group_by_query(self, mock_sdk):
        """Test GROUP BY aggregation"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "status", "type": "keyword"},
                {"name": "count", "type": "long"},
            ],
            "rows": [["success", 1200], ["error", 50], ["warning", 100]],
            "total": 3,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT status, COUNT(*) as count 
            FROM logs.doc 
            GROUP BY status
        """
        result = sdk.query_dataset_in_sql(query)

        assert len(result["rows"]) == 3
        assert result["rows"][0] == ["success", 1200]
        assert result["rows"][1] == ["error", 50]

    def test_having_clause(self, mock_sdk):
        """Test GROUP BY with HAVING clause"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "user_id", "type": "keyword"},
                {"name": "count", "type": "long"},
            ],
            "rows": [["user_123", 150], ["user_456", 200]],
            "total": 2,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT user_id, COUNT(*) as count 
            FROM logs.doc 
            GROUP BY user_id 
            HAVING COUNT(*) > 100
        """
        result = sdk.query_dataset_in_sql(query)

        assert len(result["rows"]) == 2
        assert all(row[1] > 100 for row in result["rows"])

    def test_multiple_aggregations(self, mock_sdk):
        """Test multiple aggregation functions"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "avg_duration", "type": "double"},
                {"name": "max_duration", "type": "long"},
                {"name": "min_duration", "type": "long"},
                {"name": "total_count", "type": "long"},
            ],
            "rows": [[245.5, 1000, 10, 500]],
            "total": 1,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT 
                AVG(duration) as avg_duration,
                MAX(duration) as max_duration,
                MIN(duration) as min_duration,
                COUNT(*) as total_count
            FROM logs.doc
        """
        result = sdk.query_dataset_in_sql(query)

        assert result["rows"][0][0] == 245.5  # avg
        assert result["rows"][0][1] == 1000  # max
        assert result["rows"][0][2] == 10  # min
        assert result["rows"][0][3] == 500  # count


class TestSQLTimeSeriesQueries:
    """Test SQL queries with time-series data"""

    def test_date_histogram(self, mock_sdk):
        """Test date histogram aggregation"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "time_bucket", "type": "date"},
                {"name": "count", "type": "long"},
            ],
            "rows": [
                ["2024-01-15T00:00:00Z", 100],
                ["2024-01-15T01:00:00Z", 150],
                ["2024-01-15T02:00:00Z", 120],
            ],
            "total": 3,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT 
                DATE_TRUNC('hour', timestamp) as time_bucket,
                COUNT(*) as count
            FROM logs.doc
            WHERE timestamp >= '2024-01-15T00:00:00Z'
            GROUP BY time_bucket
            ORDER BY time_bucket
        """
        result = sdk.query_dataset_in_sql(query)

        assert len(result["rows"]) == 3
        assert result["rows"][0][1] == 100
        assert result["rows"][1][1] == 150

    def test_time_range_filter(self, mock_sdk):
        """Test time range filtering"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [{"name": "count", "type": "long"}],
            "rows": [[250]],
            "total": 1,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT COUNT(*) as count
            FROM logs.doc
            WHERE timestamp BETWEEN '2024-01-15T00:00:00Z' 
                              AND '2024-01-15T23:59:59Z'
        """
        result = sdk.query_dataset_in_sql(query)

        assert result["rows"][0][0] == 250

    def test_moving_average(self, mock_sdk):
        """Test moving average calculation"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "time_bucket", "type": "date"},
                {"name": "value", "type": "double"},
                {"name": "moving_avg", "type": "double"},
            ],
            "rows": [
                ["2024-01-15T00:00:00Z", 100.0, 100.0],
                ["2024-01-15T01:00:00Z", 150.0, 125.0],
                ["2024-01-15T02:00:00Z", 120.0, 123.3],
            ],
            "total": 3,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT 
                time_bucket,
                value,
                AVG(value) OVER (
                    ORDER BY time_bucket 
                    ROWS BETWEEN 2 PRECEDING AND CURRENT ROW
                ) as moving_avg
            FROM (
                SELECT 
                    DATE_TRUNC('hour', timestamp) as time_bucket,
                    AVG(metric_value) as value
                FROM metrics.aly
                GROUP BY time_bucket
            )
            ORDER BY time_bucket
        """
        result = sdk.query_dataset_in_sql(query)

        assert len(result["rows"]) == 3
        assert result["rows"][0][2] == 100.0  # First moving avg


class TestSQLJoins:
    """Test SQL JOIN operations"""

    def test_inner_join(self, mock_sdk):
        """Test INNER JOIN"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "user_id", "type": "keyword"},
                {"name": "user_name", "type": "text"},
                {"name": "action", "type": "keyword"},
            ],
            "rows": [["user_123", "Alice", "login"], ["user_456", "Bob", "logout"]],
            "total": 2,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT u.user_id, u.name as user_name, l.action
            FROM users.doc u
            INNER JOIN logs.doc l ON u.user_id = l.user_id
        """
        result = sdk.query_dataset_in_sql(query)

        assert len(result["rows"]) == 2
        assert result["rows"][0] == ["user_123", "Alice", "login"]

    def test_left_join(self, mock_sdk):
        """Test LEFT JOIN"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "user_id", "type": "keyword"},
                {"name": "user_name", "type": "text"},
                {"name": "last_login", "type": "date"},
            ],
            "rows": [
                ["user_123", "Alice", "2024-01-15T10:00:00Z"],
                ["user_789", "Charlie", None],
            ],
            "total": 2,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT u.user_id, u.name as user_name, l.timestamp as last_login
            FROM users.doc u
            LEFT JOIN logs.doc l ON u.user_id = l.user_id AND l.action = 'login'
        """
        result = sdk.query_dataset_in_sql(query)

        assert len(result["rows"]) == 2
        assert result["rows"][1][2] is None  # Charlie has no login


class TestSQLSubqueries:
    """Test SQL subqueries and CTEs"""

    def test_subquery_in_where(self, mock_sdk):
        """Test subquery in WHERE clause"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "user_id", "type": "keyword"},
                {"name": "total_actions", "type": "long"},
            ],
            "rows": [["user_123", 250], ["user_456", 300]],
            "total": 2,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT user_id, COUNT(*) as total_actions
            FROM logs.doc
            WHERE user_id IN (
                SELECT user_id 
                FROM users.doc 
                WHERE account_type = 'premium'
            )
            GROUP BY user_id
        """
        result = sdk.query_dataset_in_sql(query)

        assert len(result["rows"]) == 2
        assert result["rows"][0][1] == 250

    def test_common_table_expression(self, mock_sdk):
        """Test CTE (WITH clause)"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "user_id", "type": "keyword"},
                {"name": "error_rate", "type": "double"},
            ],
            "rows": [["user_123", 0.05], ["user_456", 0.12]],
            "total": 2,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            WITH error_counts AS (
                SELECT 
                    user_id,
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as errors
                FROM logs.doc
                GROUP BY user_id
            )
            SELECT 
                user_id,
                CAST(errors AS DOUBLE) / CAST(total AS DOUBLE) as error_rate
            FROM error_counts
            WHERE errors > 0
        """
        result = sdk.query_dataset_in_sql(query)

        assert len(result["rows"]) == 2
        assert result["rows"][0][1] == 0.05


class TestSQLCaseStatements:
    """Test SQL CASE statements"""

    def test_simple_case(self, mock_sdk):
        """Test simple CASE statement"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "status_code", "type": "keyword"},
                {"name": "category", "type": "keyword"},
                {"name": "count", "type": "long"},
            ],
            "rows": [
                ["200", "Success", 1500],
                ["404", "Client Error", 50],
                ["500", "Server Error", 10],
            ],
            "total": 3,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT 
                status_code,
                CASE 
                    WHEN status_code < '300' THEN 'Success'
                    WHEN status_code < '400' THEN 'Redirect'
                    WHEN status_code < '500' THEN 'Client Error'
                    ELSE 'Server Error'
                END as category,
                COUNT(*) as count
            FROM logs.doc
            GROUP BY status_code, category
        """
        result = sdk.query_dataset_in_sql(query)

        assert len(result["rows"]) == 3
        assert result["rows"][0][1] == "Success"

    def test_case_with_aggregation(self, mock_sdk):
        """Test CASE statement with aggregation"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "success_count", "type": "long"},
                {"name": "error_count", "type": "long"},
            ],
            "rows": [[1500, 60]],
            "total": 1,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT 
                SUM(CASE WHEN status_code < '400' THEN 1 ELSE 0 END) as success_count,
                SUM(CASE WHEN status_code >= '400' THEN 1 ELSE 0 END) as error_count
            FROM logs.doc
        """
        result = sdk.query_dataset_in_sql(query)

        assert result["rows"][0][0] == 1500
        assert result["rows"][0][1] == 60


class TestSQLErrorHandling:
    """Test SQL error handling"""

    def test_syntax_error(self, mock_sdk):
        """Test SQL syntax error"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Syntax error in SQL query"
        mock_response.json.side_effect = ValueError("No JSON")
        sdk.session.request.return_value = mock_response

        query = "SELECT * FORM logs.doc"  # Typo: FORM instead of FROM

        with pytest.raises(InfinoError) as exc_info:
            sdk.sql(query)

        assert exc_info.value.status_code() == 400

    def test_invalid_dataset(self, mock_sdk):
        """Test query on non-existent dataset"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Dataset not found"
        mock_response.json.side_effect = ValueError("No JSON")
        sdk.session.request.return_value = mock_response

        query = "SELECT * FROM nonexistent_dataset.doc"

        with pytest.raises(InfinoError) as exc_info:
            sdk.query_dataset_in_sql(query)

        assert exc_info.value.status_code() == 404

    def test_empty_result_set(self, mock_sdk):
        """Test query with no matching results"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [{"name": "user_id", "type": "keyword"}],
            "rows": [],
            "total": 0,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = "SELECT user_id FROM logs.doc WHERE user_id = 'nonexistent'"
        result = sdk.query_dataset_in_sql(query)

        assert result["total"] == 0
        assert len(result["rows"]) == 0


class TestSQLWindowFunctions:
    """Test SQL window functions"""

    def test_row_number(self, mock_sdk):
        """Test ROW_NUMBER() window function"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "user_id", "type": "keyword"},
                {"name": "timestamp", "type": "date"},
                {"name": "row_num", "type": "long"},
            ],
            "rows": [
                ["user_123", "2024-01-15T10:00:00Z", 1],
                ["user_123", "2024-01-15T11:00:00Z", 2],
                ["user_456", "2024-01-15T10:30:00Z", 1],
            ],
            "total": 3,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT 
                user_id,
                timestamp,
                ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY timestamp) as row_num
            FROM logs.doc
        """
        result = sdk.query_dataset_in_sql(query)

        assert len(result["rows"]) == 3
        assert result["rows"][0][2] == 1
        assert result["rows"][1][2] == 2

    def test_rank_function(self, mock_sdk):
        """Test RANK() window function"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "user_id", "type": "keyword"},
                {"name": "score", "type": "long"},
                {"name": "rank", "type": "long"},
            ],
            "rows": [["user_123", 100, 1], ["user_456", 95, 2], ["user_789", 90, 3]],
            "total": 3,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT 
                user_id,
                score,
                RANK() OVER (ORDER BY score DESC) as rank
            FROM user_scores.doc
        """
        result = sdk.query_dataset_in_sql(query)

        assert len(result["rows"]) == 3
        assert result["rows"][0][2] == 1  # Highest score gets rank 1


class TestSQLIndexTypes:
    """Test SQL queries across different index types"""

    def test_document_index_query(self, mock_sdk):
        """Test query on document index (.doc)"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [{"name": "title", "type": "text"}],
            "rows": [["Test Document"]],
            "total": 1,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = "SELECT title FROM documents.doc LIMIT 1"
        result = sdk.query_dataset_in_sql(query)

        assert result["rows"][0][0] == "Test Document"

    def test_analytics_index_query(self, mock_sdk):
        """Test query on analytics index (.aly)"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [
                {"name": "metric_name", "type": "keyword"},
                {"name": "avg_value", "type": "double"},
            ],
            "rows": [["cpu_usage", 45.5], ["memory_usage", 62.3]],
            "total": 2,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = """
            SELECT metric_name, AVG(value) as avg_value
            FROM metrics.aly
            GROUP BY metric_name
        """
        result = sdk.query_dataset_in_sql(query)

        assert len(result["rows"]) == 2
        assert result["rows"][0][1] == 45.5

    def test_keyword_index_query(self, mock_sdk):
        """Test query on keyword index (.kwd)"""
        sdk, mock_requests = mock_sdk

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "columns": [{"name": "tag", "type": "keyword"}],
            "rows": [["important"], ["urgent"]],
            "total": 2,
        }
        mock_response.text = json.dumps(mock_response.json.return_value)
        sdk.session.request.return_value = mock_response

        query = "SELECT DISTINCT tag FROM tags.kwd"
        result = sdk.query_dataset_in_sql(query)

        assert len(result["rows"]) == 2
