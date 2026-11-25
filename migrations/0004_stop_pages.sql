-- Per-domain stop page branding. Each custom domain can restyle the
-- "Whoa, wait a second!" interstitial served at {domain}/p/stop.
ALTER TABLE domains ADD COLUMN stop_brand   TEXT;  -- shown instead of "Privo"
ALTER TABLE domains ADD COLUMN stop_logo    TEXT;  -- https image URL, replaces the hand icon
ALTER TABLE domains ADD COLUMN stop_color   TEXT;  -- #rgb/#rrggbb accent
ALTER TABLE domains ADD COLUMN stop_message TEXT;  -- extra line under the lede
