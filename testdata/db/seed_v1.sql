-- Data for the schema v1 snapshot. Portable between SQLite and Postgres
-- except timestamps and booleans, which build.sh / v1_seed.sql adapt.
-- :TS(ms) is a placeholder replaced per database.

INSERT INTO schema_migrations (version, applied_at) VALUES (1, :TS(1700000000000));

INSERT INTO hosts (id, name, first_seen, last_seen, conn_count, req_count, bytes_out, tls_seen, plaintext_seen) VALUES
  (1, 'api.example.com',   :TS(1700000000000), :TS(1700003600000), 42, 0,  21504, :TRUE,  :FALSE),
  (2, 'plain.example.com', :TS(1700000001000), :TS(1700000500000),  3, 7,   1200, :FALSE, :TRUE),
  (3, 'cdn.example.com',   :TS(1700000002000), :TS(1700000002000),  1, 0,    517, :TRUE,  :FALSE),
  (4, '198.51.100.7',      :TS(1700000003000), :TS(1700000003000),  1, 0,     16, :FALSE, :TRUE);

INSERT INTO host_ips (host_id, ip, expires_at) VALUES
  (1, '192.0.2.10',   :TS(1700000300000)),
  (2, '192.0.2.20',   :TS(1700000300000)),
  (3, '192.0.2.50',   :TS(1700000302000)),
  (3, '2001:db8::50', :TS(1700000302000));

INSERT INTO baseline_entries (profile, host, source, added_at) VALUES
  ('default', 'api.example.com',   'learned', :TS(1700000000000)),
  ('default', 'plain.example.com', 'learned', :TS(1700000001000)),
  ('work',    'api.example.com',   'manual',  :TS(1700000000000));

INSERT INTO alert_state (key, last_alerted, acknowledged) VALUES
  ('198.51.100.7|/opt/agent/bin/agent', :TS(1700000003000), :FALSE),
  ('plain.example.com|/usr/bin/curl',   :TS(1700000001000), :TRUE);

INSERT INTO events (id, ts, kind, host, schema_version, payload) VALUES
  (1, :TS(1700000000000), 'flow',  'api.example.com', 1,
     '{"pid":100,"process_path":"/usr/bin/curl","proto":"tcp","dst_ip":"192.0.2.10","dst_port":443,"hostname":"api.example.com","url":null,"security":"tls","bytes_out":512,"kind":"new_flow"}'),
  (2, :TS(1700000003000), 'flow',  NULL, 1,
     '{"pid":200,"process_path":"/opt/agent/bin/agent","proto":"tcp","dst_ip":"198.51.100.7","dst_port":8443,"hostname":null,"url":null,"security":"plaintext","bytes_out":16,"kind":"new_flow"}'),
  (3, :TS(1700000003000), 'alert', NULL, 1,
     '{"dst_ip":"198.51.100.7","dst_port":8443,"process_path":"/opt/agent/bin/agent","score":80,"reason":"raw_ip"}'),
  (4, :TS(1700000004000), 'audit', NULL, 1,
     '{"message":"mode changed: learn -> caution"}');
