import time

import pytest
from fixtures.common_types import Lsn
from fixtures.log_helper import log
from fixtures.neon_fixtures import (
    Endpoint,
    NeonEnv,
    NeonEnvBuilder,
    last_flush_lsn_upload,
    tenant_get_shards,
)
from fixtures.pageserver.utils import wait_for_last_record_lsn
from fixtures.utils import query_scalar


#
# Create read-only compute nodes, anchored at historical points in time.
#
# This is very similar to the 'test_branch_behind' test, but instead of
# creating branches, creates read-only nodes.
#
def test_readonly_node(neon_simple_env: NeonEnv):
    env = neon_simple_env
    endpoint_main = env.endpoints.create_start("main")

    env.pageserver.allowed_errors.extend(
        [
            ".*basebackup .* failed: invalid basebackup lsn.*",
            ".*page_service.*handle_make_lsn_lease.*.*tried to request a page version that was garbage collected",
        ]
    )

    main_pg_conn = endpoint_main.connect()
    main_cur = main_pg_conn.cursor()

    # Create table, and insert the first 100 rows
    main_cur.execute("CREATE TABLE foo (t text)")

    main_cur.execute(
        """
        INSERT INTO foo
            SELECT 'long string to consume some space' || g
            FROM generate_series(1, 100) g
    """
    )
    main_cur.execute("SELECT pg_current_wal_insert_lsn()")
    lsn_a = query_scalar(main_cur, "SELECT pg_current_wal_insert_lsn()")
    log.info("LSN after 100 rows: " + lsn_a)

    # Insert some more rows. (This generates enough WAL to fill a few segments.)
    main_cur.execute(
        """
        INSERT INTO foo
            SELECT 'long string to consume some space' || g
            FROM generate_series(1, 200000) g
    """
    )
    lsn_b = query_scalar(main_cur, "SELECT pg_current_wal_insert_lsn()")
    log.info("LSN after 200100 rows: " + lsn_b)

    # Insert many more rows. This generates enough WAL to fill a few segments.
    main_cur.execute(
        """
        INSERT INTO foo
            SELECT 'long string to consume some space' || g
            FROM generate_series(1, 200000) g
    """
    )

    lsn_c = query_scalar(main_cur, "SELECT pg_current_wal_insert_lsn()")
    log.info("LSN after 400100 rows: " + lsn_c)

    # Create first read-only node at the point where only 100 rows were inserted
    endpoint_hundred = env.endpoints.create_start(
        branch_name="main", endpoint_id="ep-readonly_node_hundred", lsn=lsn_a
    )

    # And another at the point where 200100 rows were inserted
    endpoint_more = env.endpoints.create_start(
        branch_name="main", endpoint_id="ep-readonly_node_more", lsn=lsn_b
    )

    # On the 'hundred' node, we should see only 100 rows
    hundred_pg_conn = endpoint_hundred.connect()
    hundred_cur = hundred_pg_conn.cursor()
    hundred_cur.execute("SELECT count(*) FROM foo")
    assert hundred_cur.fetchone() == (100,)

    # On the 'more' node, we should see 100200 rows
    more_pg_conn = endpoint_more.connect()
    more_cur = more_pg_conn.cursor()
    more_cur.execute("SELECT count(*) FROM foo")
    assert more_cur.fetchone() == (200100,)

    # All the rows are visible on the main branch
    main_cur.execute("SELECT count(*) FROM foo")
    assert main_cur.fetchone() == (400100,)

    # Check creating a node at segment boundary
    endpoint = env.endpoints.create_start(
        branch_name="main",
        endpoint_id="ep-branch_segment_boundary",
        lsn=Lsn("0/3000000"),
    )
    cur = endpoint.connect().cursor()
    cur.execute("SELECT 1")
    assert cur.fetchone() == (1,)

    # Create node at pre-initdb lsn
    with pytest.raises(Exception, match="invalid basebackup lsn"):
        # compute node startup with invalid LSN should fail
        env.endpoints.create_start(
            branch_name="main",
            endpoint_id="ep-readonly_node_preinitdb",
            lsn=Lsn("0/42"),
        )


def test_readonly_node_gc(neon_env_builder: NeonEnvBuilder):
    """
    Test static endpoint is protected from GC by acquiring and renewing lsn leases.
    """

    neon_env_builder.num_pageservers = 2
    # GC is manual triggered.
    env = neon_env_builder.init_start(
        initial_tenant_conf={
            # small checkpointing and compaction targets to ensure we generate many upload operations
            "checkpoint_distance": f"{128 * 1024}",
            "compaction_threshold": "1",
            "compaction_target_size": f"{128 * 1024}",
            # no PITR horizon, we specify the horizon when we request on-demand GC
            "pitr_interval": "0s",
            # disable background compaction and GC. We invoke it manually when we want it to happen.
            "gc_period": "0s",
            "compaction_period": "0s",
            # create image layers eagerly, so that GC can remove some layers
            "image_creation_threshold": "1",
            "image_layer_creation_check_threshold": "0",
            # Short lease length to fit test.
            "lsn_lease_length": "8s",
        },
        initial_tenant_shard_count=2,
    )

    ROW_COUNT = 500

    def generate_updates_on_main(
        env: NeonEnv,
        ep_main: Endpoint,
        data: int,
        start=1,
        end=ROW_COUNT,
    ) -> Lsn:
        """
        Generates some load on main branch that results in some uploads.
        """
        with ep_main.cursor() as cur:
            cur.execute(
                f"INSERT INTO t0 (v0, v1) SELECT g, '{data}' FROM generate_series({start}, {end}) g ON CONFLICT (v0) DO UPDATE SET v1 = EXCLUDED.v1"
            )
            cur.execute("VACUUM t0")
            last_flush_lsn = last_flush_lsn_upload(
                env, ep_main, env.initial_tenant, env.initial_timeline
            )
        return last_flush_lsn

    # Insert some records on main branch
    with env.endpoints.create_start("main") as ep_main:
        with ep_main.cursor() as cur:
            cur.execute("CREATE TABLE t0(v0 int primary key, v1 text)")
        lsn = None
        for i in range(2):
            lsn = generate_updates_on_main(env, ep_main, i)

        with env.endpoints.create_start(
            branch_name="main",
            endpoint_id="static",
            lsn=lsn,
        ) as ep_static:
            with ep_static.cursor() as cur:
                cur.execute("SELECT count(*) FROM t0")
                assert cur.fetchone() == (ROW_COUNT,)

            time.sleep(3)

            generate_updates_on_main(env, ep_main, i, end=100)

            # Trigger GC
            for shard, ps in tenant_get_shards(env, env.initial_tenant):
                client = ps.http_client()
                gc_result = client.timeline_gc(shard, env.initial_timeline, 0)
                log.info(f"{gc_result=}")

                assert (
                    gc_result["layers_removed"] == 0
                ), "No layers should be removed, old layers are guarded by leases."

            with ep_static.cursor() as cur:
                cur.execute("SELECT count(*) FROM t0")
                assert cur.fetchone() == (ROW_COUNT,)

        # Do some update so we can increment latest_gc_cutoff
        generate_updates_on_main(env, ep_main, i, end=100)

    # Now trigger GC again, layers should be removed.
    time.sleep(8)
    for shard, ps in tenant_get_shards(env, env.initial_tenant):
        client = ps.http_client()
        gc_result = client.timeline_gc(shard, env.initial_timeline, 0)
        log.info(f"{gc_result=}")

        assert gc_result["layers_removed"] > 0, "Old layers should be removed after leases expired."


# Similar test, but with more data, and we force checkpoints
def test_timetravel(neon_simple_env: NeonEnv):
    env = neon_simple_env
    tenant_id = env.initial_tenant
    timeline_id = env.initial_timeline
    client = env.pageserver.http_client()
    endpoint = env.endpoints.create_start("main")

    lsns = []

    with endpoint.cursor() as cur:
        cur.execute(
            """
        CREATE TABLE testtab(id serial primary key, iteration int, data text);
        INSERT INTO testtab (iteration, data) SELECT 0, 'data' FROM generate_series(1, 100000);
        """
        )
        current_lsn = Lsn(query_scalar(cur, "SELECT pg_current_wal_flush_lsn()"))
    lsns.append((0, current_lsn))

    for i in range(1, 5):
        with endpoint.cursor() as cur:
            cur.execute(f"UPDATE testtab SET iteration = {i}")
            current_lsn = Lsn(query_scalar(cur, "SELECT pg_current_wal_flush_lsn()"))
        lsns.append((i, current_lsn))

        # wait until pageserver receives that data
        wait_for_last_record_lsn(client, tenant_id, timeline_id, current_lsn)

        # run checkpoint manually to force a new layer file
        client.timeline_checkpoint(tenant_id, timeline_id)

    ##### Restart pageserver
    env.endpoints.stop_all()
    env.pageserver.stop()
    env.pageserver.start()

    for i, lsn in lsns:
        endpoint_old = env.endpoints.create_start(
            branch_name="main", endpoint_id=f"ep-old_lsn_{i}", lsn=lsn
        )
        with endpoint_old.cursor() as cur:
            assert query_scalar(cur, f"select count(*) from testtab where iteration={i}") == 100000
            assert query_scalar(cur, f"select count(*) from testtab where iteration<>{i}") == 0
