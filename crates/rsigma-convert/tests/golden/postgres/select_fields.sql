SELECT "c-uri", "CommandLine" AS cmd, "user", "userIdentity.arn", src_ip FROM security_events WHERE "cs-method" ILIKE 'POST'
SELECT count(*) AS hits, max("EventID"), SUM(bytes) AS total FROM security_events WHERE "cs-method" ILIKE 'POST'
