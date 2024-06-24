from fixtures.neon_fixtures import NeonEnv
from fixtures.pg_version import PgVersion

#
# Test that pgstat statistic is preserved across sessions
#
def test_pgstat(neon_simple_env: NeonEnv):
    env = neon_simple_env
    if env.pg_version == PgVersion.V14:
        pytest.skip("PG14 doesn't support pgstat statistic persistence")

    n = 10000
    env.neon_cli.create_branch("test_pgstat", "empty")
    endpoint = env.endpoints.create_start("test_pgstat")

    con = endpoint.connect()
    cur = con.cursor()

    cur.execute("create table t(x integer)")
    cur.execute(f"insert into t values (generate_series(1,{n}))")
    cur.execute("vacuum analyze t")
    cur.execute("select sum(x) from t")
    cur.execute("update t set x=x+1")

    cur.execute("select pg_stat_force_next_flush()")

    cur.execute("select seq_scan,seq_tup_read,n_tup_ins,n_tup_upd,n_tup_newpage_upd,n_live_tup,n_dead_tup, vacuum_count,analyze_count from pg_stat_user_tables")
    rec = cur.fetchall()[0]
    assert rec[0]==2 and rec[1]==n*2 and rec[2]==n and rec[3]==n and rec[4]==n and rec[5]==n*2 and rec[6]==n and rec[7]==1 and rec[8]==1;

    endpoint.stop();
    endpoint.start();

    con = endpoint.connect()
    cur = con.cursor()

    cur.execute("select seq_scan,seq_tup_read,n_tup_ins,n_tup_upd,n_tup_newpage_upd,n_live_tup,n_dead_tup, vacuum_count,analyze_count from pg_stat_user_tables")
    rec = cur.fetchall()[0]
    assert rec[0]==2 and rec[1]==n*2 and rec[2]==n and rec[3]==n and rec[4]==n and rec[5]==n*2 and rec[6]==n and rec[7]==1 and rec[8]==1;