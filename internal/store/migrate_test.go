package store

import (
	"path/filepath"
	"testing"
)

// Proxmox support was removed in migration 11: a database that still has servers and links from it
// loses them, and keeps everything else.
func TestForgetProxmoxMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	must(`INSERT INTO users (id, username, role, pw_hash, kek_salt, wrapped_vk, created_at) VALUES ('u1', 'owner', 'admin', 'x', x'00', x'00', 1)`)
	if err := s.CreateHost(&Host{ID: "h1", UserID: "u1", Name: "nas", Address: "10.0.0.1", Port: 22, Auth: "password", Protocol: "ssh", Theme: "auto", RDPSecurity: "any", RDPOptions: "{}"}); err != nil {
		t.Fatal(err)
	}
	// The state of a database from before this release: a server, a host linked to it, and version 10.
	must(`INSERT INTO proxmox_servers (id, user_id, address, token_id, secret_blob, fingerprint, created_at) VALUES ('p1', 'u1', 'https://pve:8006', 'a@pve!b', x'01', 'AA', 1)`)
	must(`UPDATE hosts SET proxmox_server_id='p1', proxmox_vmid=102, proxmox_type='qemu' WHERE id='h1'`)
	must(`DELETE FROM schema_version WHERE version > 10`)
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var servers, linked int
	s.db.QueryRow(`SELECT COUNT(*) FROM proxmox_servers`).Scan(&servers)
	s.db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE proxmox_server_id IS NOT NULL OR proxmox_vmid != 0 OR proxmox_type != ''`).Scan(&linked)
	if servers != 0 || linked != 0 {
		t.Fatalf("servers=%d linked hosts=%d after the migration", servers, linked)
	}
	if h, err := s.GetHost("h1", "u1"); err != nil || h.Name != "nas" {
		t.Fatalf("the host did not survive: %v %v", h, err)
	}
	// And hosts still save normally with the leftover columns in place.
	if err := s.UpdateHost(&Host{ID: "h1", UserID: "u1", Name: "nas2", Address: "10.0.0.1", Port: 22, Auth: "password", Protocol: "ssh", Theme: "auto", RDPSecurity: "any", RDPOptions: "{}"}); err != nil {
		t.Fatal(err)
	}
}
