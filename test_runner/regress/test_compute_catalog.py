from __future__ import annotations

import logging

import requests
from fixtures.neon_fixtures import NeonEnv, logical_replication_sync

TEST_DB_NAMES = [
    {
        "name": "neondb",
        "owner": "cloud_admin",
    },
    {
        "name": "db with spaces",
        "owner": "cloud_admin",
    },
    {
        "name": "db with%20spaces ",
        "owner": "cloud_admin",
    },
    {
        "name": "db with whitespaces	",
        "owner": "cloud_admin",
    },
    {
        "name": "injective db with spaces'; SELECT pg_sleep(10);",
        "owner": "cloud_admin",
    },
    {
        "name": "db with #pound-sign and &ampersands=true",
        "owner": "cloud_admin",
    },
    {
        "name": "db with emoji 🌍",
        "owner": "cloud_admin",
    },
]


def test_compute_catalog(neon_simple_env: NeonEnv):
    """
    Create a bunch of databases with tricky names and test that we can list them
    and dump via API.
    """
    env = neon_simple_env

    endpoint = env.endpoints.create_start("main")

    # Update the spec.json file to include new databases
    # and reconfigure the endpoint to create some test databases.
    endpoint.respec_deep(
        **{
            "skip_pg_catalog_updates": False,
            "cluster": {
                "databases": TEST_DB_NAMES,
            },
        }
    )
    endpoint.reconfigure()

    client = endpoint.http_client()
    objects = client.dbs_and_roles()

    # Assert that 'cloud_admin' role exists in the 'roles' list
    assert any(
        role["name"] == "cloud_admin" for role in objects["roles"]
    ), "The 'cloud_admin' role is missing"

    # Assert that 'postgres' database exists in the 'databases' list
    assert any(
        db["name"] == "postgres" for db in objects["databases"]
    ), "The 'postgres' database is missing"

    # Check other databases
    for test_db in TEST_DB_NAMES:
        db = next((db for db in objects["databases"] if db["name"] == test_db["name"]), None)
        assert db is not None, f"The '{test_db['name']}' database is missing"
        assert (
            db["owner"] == test_db["owner"]
        ), f"The '{test_db['name']}' database has incorrect owner"

        ddl = client.database_schema(database=test_db["name"])

        # Check that it looks like a valid PostgreSQL dump
        assert "-- PostgreSQL database dump" in ddl

        # Check that it doesn't contain health_check and migration traces.
        # They are only created in system `postgres` database, so by checking
        # that we ensure that we dump right databases.
        assert "health_check" not in ddl, f"The '{test_db['name']}' database contains health_check"
        assert "migration" not in ddl, f"The '{test_db['name']}' database contains migrations data"

    try:
        client.database_schema(database="nonexistentdb")
        raise AssertionError("Expected HTTPError was not raised")
    except requests.exceptions.HTTPError as e:
        assert (
            e.response.status_code == 404
        ), f"Expected 404 status code, but got {e.response.status_code}"


def test_compute_create_databases(neon_simple_env: NeonEnv):
    """
    Test that compute_ctl can create and work with databases with special
    characters (whitespaces, %, tabs, etc.) in the name.
    """
    env = neon_simple_env

    # Create and start endpoint so that neon_local put all the generated
    # stuff into the spec.json file.
    endpoint = env.endpoints.create_start("main")

    # Update the spec.json file to include new databases
    # and reconfigure the endpoint to apply the changes.
    endpoint.respec_deep(
        **{
            "skip_pg_catalog_updates": False,
            "cluster": {
                "databases": TEST_DB_NAMES,
            },
        }
    )
    endpoint.reconfigure()

    for db in TEST_DB_NAMES:
        # Check that database has a correct name in the system catalog
        with endpoint.cursor() as cursor:
            cursor.execute("SELECT datname FROM pg_database WHERE datname = %s", (db["name"],))
            catalog_db = cursor.fetchone()
            assert catalog_db is not None
            assert len(catalog_db) == 1
            assert catalog_db[0] == db["name"]

        # Check that we can connect to this database without any issues
        with endpoint.cursor(dbname=db["name"]) as cursor:
            cursor.execute("SELECT * FROM current_database()")
            curr_db = cursor.fetchone()
            assert curr_db is not None
            assert len(curr_db) == 1
            assert curr_db[0] == db["name"]


def test_dropdb_with_subscription(neon_simple_env: NeonEnv):
    """
    Test that compute_ctl can drop a database that has a logical replication subscription.
    """
    env = neon_simple_env

    # Create and start endpoint so that neon_local put all the generated
    # stuff into the spec.json file.
    endpoint = env.endpoints.create_start("main")

    TEST_DB_NAMES = [
        {
            "name": "neondb",
            "owner": "cloud_admin",
        },
        {
            "name": "subscriber_db",
            "owner": "cloud_admin",
        },
        {
            "name": "publisher_db",
            "owner": "cloud_admin",
        },
    ]

    # Update the spec.json file to create the databases
    # and reconfigure the endpoint to apply the changes.
    endpoint.respec_deep(
        **{
            "skip_pg_catalog_updates": False,
            "cluster": {
                "databases": TEST_DB_NAMES,
            },
        }
    )
    endpoint.reconfigure()

    # connect to the publisher_db and create a publication
    with endpoint.cursor(dbname="publisher_db") as cursor:
        cursor.execute("CREATE PUBLICATION mypub FOR ALL TABLES")
        cursor.execute("select pg_catalog.pg_create_logical_replication_slot('mysub', 'pgoutput');")
        cursor.execute("CREATE TABLE t(a int)")
        cursor.execute("INSERT INTO t VALUES (1)")

    # connect to the subscriber_db and create a subscription
    # Note that we need to create subscription with
    connstr = endpoint.connstr(dbname="publisher_db").replace("'", "''")
    with endpoint.cursor(dbname="subscriber_db") as cursor:
        cursor.execute("CREATE TABLE t(a int)")
        cursor.execute(
            f"CREATE SUBSCRIPTION mysub CONNECTION '{connstr}' PUBLICATION mypub  WITH (create_slot = false) "
        )

    # wait for the subscription to be active
    logical_replication_sync(
        endpoint, endpoint, sub_dbname="subscriber_db", pub_dbname="publisher_db"
    )

    # Check that replication is working
    with endpoint.cursor(dbname="subscriber_db") as cursor:
        cursor.execute("SELECT * FROM t")
        rows = cursor.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == 1

    # drop the subscriber_db from the list
    TEST_DB_NAMES_NEW = [
        {
            "name": "neondb",
            "owner": "cloud_admin",
        },
        {
            "name": "publisher_db",
            "owner": "cloud_admin",
        },
    ]
    # Update the spec.json file to drop the database
    # and reconfigure the endpoint to apply the changes.
    endpoint.respec_deep(
        **{
            "skip_pg_catalog_updates": False,
            "cluster": {
                "databases": TEST_DB_NAMES_NEW,
            },
            "delta_operations": [
                {"action": "delete_db", "name": "subscriber_db"},
                # also test the case when we try to delete a non-existent database
                # shouldn't happen in normal operation,
                # but can occur when failed operations are retried
                {"action": "delete_db", "name": "nonexistent_db"},
            ],
        }
    )

    logging.info("Reconfiguring the endpoint to drop the subscriber_db")
    endpoint.reconfigure()

    # Check that the subscriber_db is dropped
    with endpoint.cursor() as cursor:
        cursor.execute("SELECT datname FROM pg_database WHERE datname = %s", ("subscriber_db",))
        catalog_db = cursor.fetchone()
        assert catalog_db is None

    # Check that we can still connect to the publisher_db
    with endpoint.cursor(dbname="publisher_db") as cursor:
        cursor.execute("SELECT * FROM current_database()")
        curr_db = cursor.fetchone()
        assert curr_db is not None
        assert len(curr_db) == 1
        assert curr_db[0] == "publisher_db"
