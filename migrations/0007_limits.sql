-- Raise blob storage to 2 GB, lower database usage to 100 MB.
-- Applies to every account — previous default migrations (0005) are superseded.
UPDATE usage SET max_r2_bytes = 2147483648;
UPDATE usage SET max_d1_bytes = 104857600;
