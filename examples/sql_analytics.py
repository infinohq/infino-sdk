"""
SQL Analytics with Infino SDK

This example demonstrates:
- SQL query execution
- Aggregations and GROUP BY
- Complex joins
- Time-based analytics
"""

import os
from infino_sdk import InfinoSDK, InfinoError


def main():
    access_key = os.getenv("INFINO_ACCESS_KEY", "your_access_key")
    secret_key = os.getenv("INFINO_SECRET_KEY", "your_secret_key")
    endpoint = os.getenv("INFINO_ENDPOINT", "https://api.infino.ws")

    sdk = InfinoSDK(access_key, secret_key, endpoint)
    print("✅ Connected to Infino\n")
    
    # Simple SELECT query
    print("📊 Simple SELECT Query")
    print("-" * 50)
    query = "SELECT * FROM products LIMIT 10"
    try:
        result = sdk.query_dataset_in_sql(query)
        rows = result.get("rows", [])
        print(f"Retrieved {len(rows)} products")
        if rows:
            print(f"Sample: {rows[0]}")
    except InfinoError as e:
        print(f"❌ Query failed: {e.message}")

    # Filtering with WHERE clause
    print("\n\n📊 Filtering with WHERE")
    print("-" * 50)
    query = """
    SELECT name, price, category 
    FROM products 
    WHERE price > 50 AND in_stock = true
    ORDER BY price DESC
    LIMIT 20
    """
    try:
        result = sdk.query_dataset_in_sql(query)
        rows = result.get("rows", [])
        print(f"Found {len(rows)} in-stock products over $50")
        for row in rows[:5]:
            print(f"  - {row.get('name')}: ${row.get('price')}")
    except InfinoError as e:
        print(f"❌ Query failed: {e.message}")

    # Aggregations
    print("\n\n📊 Aggregation Queries")
    print("-" * 50)
    query = """
    SELECT 
        category,
        COUNT(*) as product_count,
        AVG(price) as avg_price,
        MIN(price) as min_price,
        MAX(price) as max_price,
        SUM(price) as total_value
    FROM products
    GROUP BY category
    ORDER BY product_count DESC
    """
    try:
        result = sdk.query_dataset_in_sql(query)
        rows = result.get("rows", [])
        print(f"Category Statistics:\n")
        for row in rows:
            print(f"  {row.get('category')}:")
            print(f"    Count: {row.get('product_count')}")
            print(f"    Avg Price: ${row.get('avg_price', 0):.2f}")
            print(f"    Range: ${row.get('min_price', 0):.2f} - ${row.get('max_price', 0):.2f}")
            print()
    except InfinoError as e:
        print(f"❌ Query failed: {e.message}")

    # HAVING clause
    print("\n\n📊 GROUP BY with HAVING")
    print("-" * 50)
    query = """
    SELECT 
        category,
        COUNT(*) as count,
        AVG(rating) as avg_rating
    FROM products
    GROUP BY category
    HAVING COUNT(*) > 100 AND AVG(rating) > 4.0
    ORDER BY avg_rating DESC
    """
    try:
        result = sdk.query_dataset_in_sql(query)
        rows = result.get("rows", [])
        print(f"Top-rated categories (>100 products, >4.0 rating):\n")
        for row in rows:
            print(f"  {row.get('category')}: {row.get('avg_rating'):.1f} ⭐ ({row.get('count')} products)")
    except InfinoError as e:
        print(f"❌ Query failed: {e.message}")

    # Time-based analytics
    print("\n\n📊 Time-based Analytics")
    print("-" * 50)
    query = """
    SELECT 
        DATE_TRUNC('day', created_at) as day,
        COUNT(*) as orders,
        SUM(total_amount) as revenue
    FROM orders
    WHERE created_at >= '2024-01-01'
    GROUP BY DATE_TRUNC('day', created_at)
    ORDER BY day DESC
    LIMIT 30
    """
    try:
        result = sdk.query_dataset_in_sql(query)
        rows = result.get("rows", [])
        print(f"Daily Order Statistics (Last 30 days):\n")
        for row in rows[:10]:
            print(f"  {row.get('day')}: {row.get('orders')} orders, ${row.get('revenue', 0):.2f} revenue")
    except InfinoError as e:
        print(f"❌ Query failed: {e.message}")

    # Window functions
    print("\n\n📊 Window Functions")
    print("-" * 50)
    query = """
    SELECT 
        name,
        category,
        price,
        RANK() OVER (PARTITION BY category ORDER BY price DESC) as price_rank
    FROM products
    WHERE category IN ('electronics', 'home')
    LIMIT 20
    """
    try:
        result = sdk.query_dataset_in_sql(query)
        rows = result.get("rows", [])
        print(f"Top products by price in each category:\n")
        current_category = None
        for row in rows:
            if row.get('category') != current_category:
                current_category = row.get('category')
                print(f"\n  {current_category}:")
            print(f"    #{row.get('price_rank')} {row.get('name')}: ${row.get('price')}")
    except InfinoError as e:
        print(f"❌ Query failed: {e.message}")

    # Complex subquery
    print("\n\n📊 Subquery Example")
    print("-" * 50)
    query = """
    SELECT 
        p.category,
        p.name,
        p.price
    FROM products p
    WHERE p.price > (
        SELECT AVG(price) 
        FROM products 
        WHERE category = p.category
    )
    LIMIT 15
    """
    try:
        result = sdk.query_dataset_in_sql(query)
        rows = result.get("rows", [])
        print(f"Products priced above their category average:\n")
        for row in rows:
            print(f"  [{row.get('category')}] {row.get('name')}: ${row.get('price')}")
    except InfinoError as e:
        print(f"❌ Query failed: {e.message}")

    # CASE statements
    print("\n\n📊 CASE Statements")
    print("-" * 50)
    query = """
    SELECT 
        name,
        price,
        CASE 
            WHEN price < 25 THEN 'Budget'
            WHEN price < 100 THEN 'Mid-range'
            WHEN price < 500 THEN 'Premium'
            ELSE 'Luxury'
        END as price_tier,
        category
    FROM products
    WHERE category = 'electronics'
    LIMIT 20
    """
    try:
        result = sdk.query_dataset_in_sql(query)
        rows = result.get("rows", [])
        print(f"Products by price tier:\n")
        for row in rows:
            print(f"  {row.get('name')} ({row.get('price_tier')}): ${row.get('price')}")
    except InfinoError as e:
        print(f"❌ Query failed: {e.message}")


if __name__ == "__main__":
    main()
