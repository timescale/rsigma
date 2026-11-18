SELECT * FROM security_events WHERE "CommandLine"" OR 1=1; --" ILIKE 'whoami' AND title_field ILIKE '{rule.title}' AND id_field ILIKE '{rule.id}'
