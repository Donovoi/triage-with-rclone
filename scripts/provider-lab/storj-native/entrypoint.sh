#!/bin/sh
set -eu
export HOME=/work TMPDIR=/work GOMAXPROCS=2 GOGC=35
export STORJ_TEST_POSTGRES='postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable'
export STORJ_TEST_COCKROACH=omit STORJ_TEST_TIDB=omit
cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [ -d /work/pgdata ]; then
        pg_ctl -D /work/pgdata -m immediate -w -t 15 stop >/work/postgres-stop.log 2>&1 || status=1
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM
initdb -D /work/pgdata --locale=C --encoding=UTF8 --auth-local=trust --auth-host=trust >/work/initdb.log 2>&1
pg_ctl -D /work/pgdata -l /work/postgres.log -o "-h 127.0.0.1 -k /work -p 5432 -c shared_buffers=16MB -c max_connections=80 -c fsync=off -c synchronous_commit=off" -w -t 20 start
/opt/triage/planet.test -test.run '^TestSyntheticNetwork$' -test.v -test.timeout 120s
