-- Data added on top of seed_v2.sql for the schema v3 snapshot: a database that ran v2, was
-- migrated with 0003, then counted per process + host and flagged an unresolved host.
-- Same placeholders as seed_v1.sql.

INSERT INTO schema_migrations (version, applied_at) VALUES (3, :TS(1700200000000));

INSERT INTO hosts (name, first_seen, last_seen, conn_count, req_count, bytes_out, tls_seen, plaintext_seen, unresolved) VALUES
  ('public.example.com', :TS(1700200001000), :TS(1700200001000), 1, 0, 512, :TRUE, :FALSE, :TRUE);

INSERT INTO process_hosts (process, host, first_seen, last_seen, conn_count, req_count, bytes_out) VALUES
  ('/usr/bin/curl', 'plain.example.com', :TS(1700200002000), :TS(1700200002000), 1, 1, 96),
  ('/usr/bin/curl', 'public.example.com', :TS(1700200001000), :TS(1700200001000), 1, 0, 512);

INSERT INTO events (id, ts, kind, module, host, schema_version, payload) VALUES
  (7, :TS(1700200003000), 'alert', NULL, 'public.example.com', 3,
     '{"dst_ip":"192.0.2.12","dst_port":443,"process_path":"/usr/bin/curl","score":0,"reason":"unlisted_host","notes":{}}');
