-- Data added on top of seed_v3.sql for the schema v4 snapshot: a database that ran v3, was
-- migrated with 0004, then counted two hours for one host. Same placeholders as seed_v1.sql.

INSERT INTO schema_migrations (version, applied_at) VALUES (4, :TS(1700300000000));

INSERT INTO host_hours (host, hour, conn_count, req_count, bytes_out) VALUES
  ('api.example.com', :TS(1700298000000), 3, 0, 1536),
  ('api.example.com', :TS(1700301600000), 1, 0, 512);
