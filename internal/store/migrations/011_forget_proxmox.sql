-- Proxmox support was removed. Forget the connected servers (and their sealed API tokens) and the
-- links from hosts. The empty table and the three unused host columns stay: SQLite cannot drop a
-- column that has a foreign key, and they hold nothing.
DELETE FROM proxmox_servers;
UPDATE hosts SET proxmox_server_id = NULL, proxmox_vmid = 0, proxmox_type = '';
