-- Lower per-user limits: 1 GB of R2 blob storage, 300 MB of D1 usage.
-- Rows that were explicitly raised keep their higher cap; rows still on
-- the old defaults (3 GB / 1 GB) move to the new ones.
UPDATE usage SET max_r2_bytes = 1073741824 WHERE max_r2_bytes = 3221225472;
UPDATE usage SET max_d1_bytes = 314572800 WHERE max_d1_bytes = 1073741824;
