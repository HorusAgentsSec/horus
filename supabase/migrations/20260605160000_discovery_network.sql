-- Extend discovery sources to support private-network discovery (CIDR ping sweep),
-- alongside the existing passive domain discovery.
--
-- A source is now either kind='domain' (uses `domain`) or kind='network' (uses
-- `network_cidr`). Network discovery is ACTIVE (it pings the range) and only ever
-- targets private/RFC1918 ranges, creating internal assets — see core/discovery.py.

alter table discovery_sources alter column domain drop not null;

alter table discovery_sources
  add column kind text not null default 'domain' check (kind in ('domain', 'network'));

alter table discovery_sources
  add column network_cidr text;
