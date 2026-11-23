package server

import (
	"bytes"
	"context"
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
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/thatguy-za/webterm/internal/rfb"
)

// fakeVNC accepts connections and speaks just enough RFB 3.8 for a login, then ServerInit.
type fakeVNC struct {
	port    int
	logins  chan string
	handler func(c net.Conn, f *fakeVNC)
	mu      sync.Mutex
	cert    tls.Certificate
}

func newCert() tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "vnc"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (f *fakeVNC) certificate() tls.Certificate { f.mu.Lock(); defer f.mu.Unlock(); return f.cert }
func (f *fakeVNC) setCert(c tls.Certificate)    { f.mu.Lock(); f.cert = c; f.mu.Unlock() }

func rfbResponse(challenge []byte, password string) []byte {
	b, _ := rfb.VNCResponse(challenge, password)
	return b
}

func newFakeVNC(t *testing.T, handler func(c net.Conn, f *fakeVNC)) *fakeVNC {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeVNC{port: ln.Addr().(*net.TCPAddr).Port, logins: make(chan string, 8), handler: handler}
	f.cert = newCert()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); f.handler(c, f) }()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func readFull(c net.Conn, n int) []byte {
	b := make([]byte, n)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	io.ReadFull(c, b)
	return b
}

func u32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }

// finish does what follows a good login: read ClientInit, send a ServerInit.
func finish(c net.Conn) {
	readFull(c, 1)
	c.Write([]byte("SERVERINIT"))
}

func vncPasswordServer(c net.Conn, f *fakeVNC) {
	c.Write([]byte("RFB 003.008\n"))
	readFull(c, 12)
	c.Write([]byte{1, 2})
	readFull(c, 1)
	challenge := bytes.Repeat([]byte{7, 9}, 8)
	c.Write(challenge)
	got := readFull(c, 16)
	want := rfbResponse(challenge, "s3cret")
	if bytes.Equal(got, want) {
		c.Write(u32(0))
		finish(c)
		return
	}
	c.Write(u32(1))
	c.Write(u32(uint32(len("Authentication failed"))))
	c.Write([]byte("Authentication failed"))
}

func vncHost(t *testing.T, u *client, port int, extra map[string]any) string {
	body := map[string]any{"protocol": "vnc", "address": "127.0.0.1", "port": port}
	for k, v := range extra {
		body[k] = v
	}
	return addHost(t, u, "pi", port, body)
}

// dialVNC opens the VNC WebSocket.
func dialVNC(t *testing.T, base string, cl *client, hostID string) *wsClient {
	w := dialWSPath(t, base, cl, "/api/ws/vnc/"+hostID)
	return w
}

func (w *wsClient) readBinary(n int) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var got []byte
	for len(got) < n {
		typ, data, err := w.c.Read(ctx)
		if err != nil {
			w.t.Fatalf("read: %v", err)
		}
		if typ == websocket.MessageBinary {
			got = append(got, data...)
		}
	}
	return got
}

func (w *wsClient) writeBinary(b []byte) {
	if err := w.c.Write(context.Background(), websocket.MessageBinary, b); err != nil {
		w.t.Fatal(err)
	}
}

func TestVNCBridge(t *testing.T) {
	_, ts, u := newBridgeEnv(t)
	f := newFakeVNC(t, vncPasswordServer)
	id := vncHost(t, u, f.port, nil)
	w := dialVNC(t, ts.URL, u, id)
	if m := w.next(); m.Type != "ready" {
		t.Fatalf("expected ready, got %+v", m)
	}
	w.send(map[string]string{"type": "attach"})
	// The browser sees a server that needs no login: WebTerm has already logged in.
	if v := string(w.readBinary(12)); v != "RFB 003.008\n" {
		t.Fatalf("version: %q", v)
	}
	w.writeBinary([]byte("RFB 003.008\n"))
	if got := w.readBinary(2); got[0] != 1 || got[1] != 1 {
		t.Fatalf("security types: %v", got)
	}
	w.writeBinary([]byte{1})
	if got := w.readBinary(4); !bytes.Equal(got, []byte{0, 0, 0, 0}) {
		t.Fatalf("security result: %v", got)
	}
	// After that the real server's own messages come through untouched.
	w.writeBinary([]byte{1}) // ClientInit
	if got := string(w.readBinary(10)); got != "SERVERINIT" {
		t.Fatalf("server init: %q", got)
	}
}

func TestVNCWrongPasswordSaysWhy(t *testing.T) {
	_, ts, u := newBridgeEnv(t)
	f := newFakeVNC(t, vncPasswordServer)
	id := vncHost(t, u, f.port, map[string]any{"password": "not-it"})
	w := dialVNC(t, ts.URL, u, id)
	if m := w.next(); m.Type != "error" || !bytes.Contains([]byte(m.Message), []byte("Authentication failed")) {
		t.Fatalf("expected the server's reason, got %+v", m)
	}
}

func TestVNCUnreachableAndWrongProtocol(t *testing.T) {
	_, ts, u := newBridgeEnv(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	id := vncHost(t, u, port, nil)
	w := dialVNC(t, ts.URL, u, id)
	if m := w.next(); m.Type != "error" || !bytes.Contains([]byte(m.Message), []byte("could not reach 127.0.0.1:"+strconv.Itoa(port))) {
		t.Fatalf("expected an unreachable message, got %+v", m)
	}
	ssh := addHost(t, u, "box", 22, nil)
	if _, _, err := tryDialWS(ts.URL, u, "/api/ws/vnc/"+ssh); err == nil {
		t.Fatal("an SSH host opened as VNC")
	}
}

func veNCryptServer(c net.Conn, f *fakeVNC) {
	c.Write([]byte("RFB 003.008\n"))
	readFull(c, 12)
	c.Write([]byte{1, 19})
	readFull(c, 1)
	c.Write([]byte{0, 2})
	readFull(c, 2)
	c.Write([]byte{0, 1})
	c.Write(u32(262))
	readFull(c, 4)
	c.Write([]byte{1})
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.certificate()}})
	if tc.Handshake() != nil {
		return
	}
	h := readFull(tc, 8)
	user := readFull(tc, int(binary.BigEndian.Uint32(h)))
	pass := readFull(tc, int(binary.BigEndian.Uint32(h[4:])))
	if string(user) == "pi" && string(pass) == "s3cret" {
		tc.Write(u32(0))
		f.logins <- string(user)
		readFull(tc, 1)
		tc.Write([]byte("SERVERINIT"))
		return
	}
	tc.Write(u32(1))
}

func TestVNCCertificateIsTrustedOnFirstUse(t *testing.T) {
	_, ts, u := newBridgeEnv(t)
	f := newFakeVNC(t, veNCryptServer)
	id := vncHost(t, u, f.port, map[string]any{"username": "pi"})

	// First time: the person is asked about the certificate, and the login waits.
	w := dialVNC(t, ts.URL, u, id)
	m := w.next()
	if m.Type != "hostkey" || m.KeyType != "TLS certificate" || m.Fingerprint == "" || m.Changed {
		t.Fatalf("expected a first-use prompt, got %+v", m)
	}
	first := m.Fingerprint
	w.send(map[string]any{"type": "trust", "accept": true})
	if m := w.next(); m.Type != "ready" {
		t.Fatalf("expected ready after trusting, got %+v", m)
	}
	if got := <-f.logins; got != "pi" {
		t.Fatalf("login as %q", got)
	}

	// Second time, the same certificate needs no question.
	w2 := dialVNC(t, ts.URL, u, id)
	if m := w2.next(); m.Type != "ready" {
		t.Fatalf("a trusted certificate asked again: %+v", m)
	}

	// A different certificate is a warning, with the old fingerprint beside it.
	f.setCert(newCert())
	w3 := dialVNC(t, ts.URL, u, id)
	m3 := w3.next()
	if m3.Type != "hostkey" || !m3.Changed || m3.OldPrint != first || m3.Fingerprint == first {
		t.Fatalf("expected a changed-certificate warning, got %+v", m3)
	}
}

func TestVNCRefusedCertificateStopsTheLogin(t *testing.T) {
	_, ts, u := newBridgeEnv(t)
	f := newFakeVNC(t, veNCryptServer)
	id := vncHost(t, u, f.port, map[string]any{"username": "pi"})
	w := dialVNC(t, ts.URL, u, id)
	if m := w.next(); m.Type != "hostkey" {
		t.Fatalf("expected a prompt, got %+v", m)
	}
	w.send(map[string]any{"type": "trust", "accept": false})
	if m := w.next(); m.Type != "error" || !bytes.Contains([]byte(m.Message), []byte("not trusted")) {
		t.Fatalf("expected a refusal message, got %+v", m)
	}
}

func TestVNCHostRules(t *testing.T) {
	srv, _, u := newBridgeEnv(t)
	// VNC hosts default to port 5900, sign in with a password whatever else is asked, and have no identity.
	code, out := u.do("POST", "/api/hosts", map[string]any{"name": "pi", "protocol": "vnc", "address": "10.0.0.5", "auth": "key", "identity_id": "nope", "password": "raspberry"})
	if code != 200 || out["port"] != float64(5900) || out["auth"] != "password" || out["identity_id"] != "" || out["protocol"] != "vnc" {
		t.Fatalf("create: %d %v", code, out)
	}
	if h, _ := srv.db.GetHost(out["id"].(string), ownerID(t, srv)); h.PasswordBlob == nil || bytes.Contains(h.PasswordBlob, []byte("raspberry")) {
		t.Fatal("the VNC password is missing or stored in the clear")
	}
	// A login without a password is allowed: some servers ask for none.
	if code, _ := u.do("POST", "/api/hosts", map[string]any{"name": "open", "protocol": "vnc", "address": "10.0.0.6"}); code != 200 {
		t.Fatalf("a VNC host without a password: %d", code)
	}
	// The other protocols' endpoints refuse a VNC host, and SSH keys are not pushed to it.
	if code, o := u.do("GET", "/api/ws/rdp/"+out["id"].(string), nil); code != 400 || o["error"] != "wrong_protocol" {
		t.Fatalf("rdp endpoint on a vnc host: %d %v", code, o)
	}
	if code, o := u.do("GET", "/api/ws/ssh/"+out["id"].(string), nil); code != 400 || o["error"] != "wrong_protocol" {
		t.Fatalf("ssh endpoint on a vnc host: %d %v", code, o)
	}
}
