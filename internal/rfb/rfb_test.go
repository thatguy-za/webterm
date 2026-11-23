package rfb

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// server is a stand-in VNC server for one connection.
type server struct {
	t     *testing.T
	c     net.Conn
	minor int
}

func (s *server) write(b ...byte) { s.c.Write(b) }
func (s *server) read(n int) []byte {
	b := make([]byte, n)
	s.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	io.ReadFull(s.c, b) // a client that gave up early is fine: the test checks what the client reports
	return b
}
func (s *server) u32(v uint32)    { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); s.c.Write(b) }
func (s *server) text(msg string) { s.u32(uint32(len(msg))); s.c.Write([]byte(msg)) }

// version says hello and returns the version the client picked.
func (s *server) version() string {
	s.c.Write([]byte("RFB 003." + map[int]string{3: "003", 7: "007", 8: "008"}[s.minor] + "\n"))
	return string(s.read(12))
}

func run(t *testing.T, minor int, serve func(s *server), a Auth) (net.Conn, error) {
	t.Helper()
	cli, srv := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); defer srv.Close(); serve(&server{t: t, c: srv, minor: minor}) }()
	a.Timeout = 3 * time.Second
	c, err := Login(cli, a)
	if err != nil {
		cli.Close()
	}
	t.Cleanup(func() { cli.Close(); <-done })
	return c, err
}

func TestNoLogin(t *testing.T) {
	serve := func(s *server) { s.version(); s.write(1, secNone); s.read(1); s.u32(0) }
	if _, err := run(t, 8, serve, Auth{}); err != nil {
		t.Fatalf("no login: %v", err)
	}
	// A saved password is never silently dropped because the server offers no login.
	_, err := run(t, 8, serve, Auth{Password: "secret"})
	if err == nil || !strings.Contains(err.Error(), "does not ask for a login") {
		t.Fatalf("a saved password with an open server: %v", err)
	}
}

func vncServer(password string, minor int) func(s *server) {
	return func(s *server) {
		s.version()
		if minor == 3 {
			s.u32(secVNC)
		} else {
			s.write(1, secVNC)
			s.read(1)
		}
		challenge := bytes.Repeat([]byte{0x5a, 0xa5}, 8)
		s.c.Write(challenge)
		got := s.read(16)
		want, _ := VNCResponse(challenge, password)
		if bytes.Equal(got, want) {
			s.u32(0)
			return
		}
		s.u32(1)
		if minor == 8 {
			s.text("Authentication failed")
		}
	}
}

func TestVNCPassword(t *testing.T) {
	for _, minor := range []int{8, 7, 3} {
		if _, err := run(t, minor, vncServer("hunter2", minor), Auth{Password: "hunter2"}); err != nil {
			t.Errorf("3.%d right password: %v", minor, err)
		}
	}
	_, err := run(t, 8, vncServer("hunter2", 8), Auth{Password: "wrong"})
	if err == nil || !strings.Contains(err.Error(), "Authentication failed") {
		t.Fatalf("wrong password: %v", err)
	}
	_, err = run(t, 7, vncServer("hunter2", 7), Auth{Password: "wrong"})
	if err == nil || !strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("wrong password on 3.7: %v", err)
	}
	// Only the first eight characters count, as the protocol says.
	if _, err := run(t, 8, vncServer("12345678", 8), Auth{Password: "12345678-and-more"}); err != nil {
		t.Fatalf("a long password: %v", err)
	}
	_, err = run(t, 8, vncServer("x", 8), Auth{})
	if err == nil || !strings.Contains(err.Error(), "asks for a password") {
		t.Fatalf("no password saved: %v", err)
	}
}

func TestVNCResponseVector(t *testing.T) {
	// The DES key is the password with each byte's bits reversed: "a" (0x61) becomes 0x86.
	got, _ := VNCResponse(make([]byte, 16), "a")
	again, _ := VNCResponse(make([]byte, 16), "a\x00\x00")
	if !bytes.Equal(got, again) || bytes.Equal(got, make([]byte, 16)) {
		t.Fatalf("padding or encryption is off: %x %x", got, again)
	}
	if !bytes.Equal(got[:8], got[8:]) {
		t.Fatal("two equal blocks must encrypt equally")
	}
}

func TestOnlyUnsupportedLogins(t *testing.T) {
	_, err := run(t, 8, func(s *server) { s.version(); s.write(2, 5, 6) }, Auth{Password: "x"})
	if err == nil || !strings.Contains(err.Error(), "RealVNC") {
		t.Fatalf("RA2 only: %v", err)
	}
	_, err = run(t, 8, func(s *server) { s.version(); s.write(0); s.text("Too many connections") }, Auth{})
	if err == nil || !strings.Contains(err.Error(), "Too many connections") {
		t.Fatalf("refusal reason: %v", err)
	}
	_, err = run(t, 8, func(s *server) { s.c.Write([]byte("HTTP/1.1 400 Bad\r\n")) }, Auth{})
	if err == nil || !strings.Contains(err.Error(), "does not speak VNC") {
		t.Fatalf("not VNC: %v", err)
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vnc"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// vencryptServer offers VeNCrypt with one sub-type and checks the username and password it gets.
func vencryptServer(cert tls.Certificate, sub uint32, wantUser, wantPass string, gotUser *string) func(s *server) {
	return func(s *server) {
		s.version()
		s.write(1, secVeNCrypt)
		s.read(1)
		s.write(0, 2) // version 0.2
		s.read(2)
		s.write(0) // version accepted
		s.write(1)
		s.u32(sub)
		s.read(4)
		s.write(1) // sub-type accepted
		tc := tls.Server(s.c, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		s.c = tc
		if sub == vencryptX509Plain {
			h := s.read(8)
			u := s.read(int(binary.BigEndian.Uint32(h)))
			p := s.read(int(binary.BigEndian.Uint32(h[4:])))
			*gotUser = string(u)
			if string(u) == wantUser && string(p) == wantPass {
				s.u32(0)
			} else {
				s.u32(1)
				s.text("Invalid username or password")
			}
		}
	}
}

func TestVeNCryptPlain(t *testing.T) {
	cert := selfSigned(t)
	var got string
	var seen []byte
	a := Auth{Username: "pi", Password: "raspberry", VerifyCert: func(der []byte) error { seen = der; return nil }}
	c, err := run(t, 8, vencryptServer(cert, vencryptX509Plain, "pi", "raspberry", &got), a)
	if err != nil || got != "pi" {
		t.Fatalf("login: %v (user %q)", err, got)
	}
	if _, ok := c.(*tls.Conn); !ok {
		t.Fatalf("the session should continue over TLS, got %T", c)
	}
	if !bytes.Equal(seen, cert.Certificate[0]) {
		t.Fatal("the certificate was not handed to VerifyCert")
	}
	// A wrong password gives the server's reason.
	_, err = run(t, 8, vencryptServer(cert, vencryptX509Plain, "pi", "raspberry", &got), Auth{Username: "pi", Password: "nope"})
	if err == nil || !strings.Contains(err.Error(), "Invalid username or password") {
		t.Fatalf("wrong password: %v", err)
	}
	// Refusing the certificate stops the login, with the refusal's own message.
	_, err = run(t, 8, vencryptServer(cert, vencryptX509Plain, "pi", "raspberry", &got), Auth{Username: "pi", Password: "raspberry", VerifyCert: func([]byte) error { return fail("Certificate not trusted.") }})
	if err == nil || !strings.Contains(err.Error(), "Certificate not trusted") {
		t.Fatalf("refused certificate: %v", err)
	}
	// A server that asks for a username when none is saved says so.
	_, err = run(t, 8, vencryptServer(cert, vencryptX509Plain, "pi", "raspberry", &got), Auth{Password: "raspberry"})
	if err == nil || !strings.Contains(err.Error(), "username") {
		t.Fatalf("no username: %v", err)
	}
}

func TestServeBrowser(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	errc := make(chan error, 1)
	go func() { defer srv.Close(); errc <- ServeBrowser(srv) }()
	read := func(n int) []byte {
		b := make([]byte, n)
		cli.SetReadDeadline(time.Now().Add(3 * time.Second))
		io.ReadFull(cli, b)
		return b
	}
	if v := string(read(12)); v != "RFB 003.008\n" {
		t.Fatalf("version: %q", v)
	}
	cli.Write([]byte("RFB 003.008\n"))
	if got := read(2); got[0] != 1 || got[1] != secNone {
		t.Fatalf("security types: %v", got)
	}
	cli.Write([]byte{secNone})
	if got := read(4); !bytes.Equal(got, []byte{0, 0, 0, 0}) {
		t.Fatalf("result: %v", got)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}
