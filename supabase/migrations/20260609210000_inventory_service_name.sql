-- asset_inventory.service_name: the nmap-detected service label (e.g. "http", "ssh").
-- The scan pipeline already extracts it (detected_services[].service); persist it so the
-- Asset Detail "Detected Technologies" table can show it. Nullable: older rows predate it.
alter table asset_inventory add column if not exists service_name text;
