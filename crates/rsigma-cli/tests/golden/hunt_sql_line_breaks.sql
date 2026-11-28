-- timestamp_field: time
-- rule: Title DROP TABLE security_events; -- CR  CRLF NEL LS PS (id: id DELETE FROM security_events)
SELECT * FROM (SELECT * FROM security_events WHERE "Image" ILIKE '/usr/bin/curl') AS __hunt WHERE time >= '2026-07-01T00:00:00+00:00'::timestamptz AND time < '2026-07-02T00:00:00+00:00'::timestamptz ORDER BY time LIMIT 1000;

-- rule: Second rule (id: second id)
SELECT * FROM (SELECT * FROM security_events WHERE "Image" ILIKE '/usr/bin/wget') AS __hunt WHERE time >= '2026-07-01T00:00:00+00:00'::timestamptz AND time < '2026-07-02T00:00:00+00:00'::timestamptz ORDER BY time LIMIT 1000;
