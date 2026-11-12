-- Deterministic SQLite workload for tests/run-examples.sh: file database (locking, journal), CTEs, joins, aggregates,
-- window functions, JSON, floats, transactions and rollback.
.headers on
.mode list
PRAGMA journal_mode=DELETE;
CREATE TABLE t(id INTEGER PRIMARY KEY, grp INTEGER, name TEXT, val REAL);
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 20000)
INSERT INTO t(grp, name, val) SELECT i % 17, 'name' || (i * 7919 % 10007), (i * 37 % 1000) / 7.0 FROM n;
CREATE INDEX t_grp ON t(grp);
SELECT grp, count(*), round(sum(val), 6), min(name), max(name) FROM t GROUP BY grp ORDER BY grp LIMIT 5;
SELECT name, val, rank() OVER (PARTITION BY grp ORDER BY val DESC, id) AS r FROM t WHERE grp = 3 ORDER BY r, id LIMIT 4;
CREATE TABLE u(grp INTEGER PRIMARY KEY, label TEXT);
INSERT INTO u SELECT DISTINCT grp, printf('group-%03d', grp) FROM t;
SELECT u.label, count(t.id), printf('%.4f', avg(t.val)) FROM u JOIN t USING(grp) GROUP BY u.label ORDER BY 2 DESC, 1 LIMIT 3;
BEGIN; DELETE FROM t WHERE grp = 5; SELECT count(*) FROM t; ROLLBACK;
SELECT count(*) FROM t;
BEGIN; UPDATE t SET val = val * 2 WHERE id % 3 = 0; COMMIT;
SELECT printf('%.6f', sum(val)) FROM t;
SELECT json_object('n', count(*), 'top', (SELECT json_group_array(name) FROM (SELECT name FROM t ORDER BY val DESC, id LIMIT 3))) FROM t;
SELECT 1e308 * 10, -0.0, 0.1 + 0.2, cast(9223372036854775807 AS REAL), 7 / 2, 7 % -3, abs(-9223372036854775807);
SELECT hex(zeroblob(4)), length(randomblob(16)), upper('straße'), substr('hello world', -5), instr('abcabc', 'ca');
VACUUM;
PRAGMA integrity_check;
