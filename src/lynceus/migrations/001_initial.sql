CREATE TABLE devices(
  mac TEXT PRIMARY KEY,
  device_type TEXT NOT NULL CHECK(device_type IN ('wifi','ble','bt_classic')),
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  sighting_count INTEGER NOT NULL DEFAULT 0,
  oui_vendor TEXT,
  is_randomized INTEGER NOT NULL CHECK(is_randomized IN (0,1)),
  notes TEXT
);

CREATE TABLE locations(
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL
);

CREATE TABLE sightings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mac TEXT NOT NULL REFERENCES devices(mac),
  ts INTEGER NOT NULL,
  rssi INTEGER,
  ssid TEXT,
  location_id TEXT NOT NULL REFERENCES locations(id)
);

CREATE TABLE watchlist(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT NOT NULL,
  pattern_type TEXT NOT NULL CHECK(pattern_type IN ('mac','oui','ssid','ble_uuid')),
  severity TEXT NOT NULL CHECK(severity IN ('low','med','high')),
  description TEXT
);

CREATE TABLE alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  rule_name TEXT NOT NULL,
  mac TEXT REFERENCES devices(mac),
  message TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('low','med','high')),
  acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1))
);

CREATE INDEX idx_sightings_mac_ts ON sightings(mac, ts);
CREATE INDEX idx_sightings_ts ON sightings(ts);
CREATE INDEX idx_alerts_ts ON alerts(ts);
CREATE INDEX idx_alerts_unack ON alerts(acknowledged) WHERE acknowledged = 0;
