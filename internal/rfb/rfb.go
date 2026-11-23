// Package rfb does the first part of the VNC (RFB) protocol: the version and login handshake. WebTerm
// logs in to the VNC server itself, so the password stays on the server, and then hands the rest of
// the session to the browser's noVNC as if the server needed no login.
package rfb

import (
	"crypto/des" // #nosec G502 -- VNC password login is defined in terms of DES
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Security types from the RFB protocol.
const (
	secNone     = 1
	secVNC      = 2
	secVeNCrypt = 19
)

// VeNCrypt sub-types: a login carried over TLS with a certificate.
const (
	vencryptX509None  = 260
	vencryptX509Vnc   = 261
	vencryptX509Plain = 262
)

// Auth is what to log in with. Username is only used by servers that ask for one (VeNCrypt, as in wayvnc).
type Auth struct {
	Username, Password string
	// VerifyCert is given the server's certificate when the login runs over TLS. It decides whether to trust it.
	VerifyCert func(der []byte) error
	// Timeout bounds each read and write during the handshake.
	Timeout time.Duration
}

// Error is a failure with a message fit to show a person.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func fail(format string, a ...any) error { return &Error{fmt.Sprintf(format, a...)} }

// Login performs the client side of the handshake on conn and returns the connection to use from
// then on: conn itself, or the TLS connection wrapped around it.
func Login(conn net.Conn, a Auth) (net.Conn, error) {
	h := &hs{conn: conn, to: a.Timeout}
	if h.to == 0 {
		h.to = 30 * time.Second
	}
	ver, err := h.version()
	if err != nil {
		return nil, err
	}
	types, err := h.securityTypes(ver)
	if err != nil {
		return nil, err
	}
	have := a.Password != "" || a.Username != ""
	choice, err := choose(types, a)
	if err != nil {
		return nil, err
	}
	if ver >= 7 {
		if err := h.write([]byte{byte(choice)}); err != nil {
			return nil, err
		}
	}
	switch choice {
	case secNone:
		if have {
			return nil, fail("This server does not ask for a login, but this host has a password saved. Remove the password from the host if that is intended.")
		}
		if ver >= 8 { // 3.3 and 3.7 send no result for no login
			if err := h.result(ver); err != nil {
				return nil, err
			}
		}
		return conn, nil
	case secVNC:
		if err := h.vncAuth(a.Password); err != nil {
			return nil, err
		}
		return conn, h.result(ver)
	case secVeNCrypt:
		secured, err := h.vencrypt(a)
		if err != nil {
			return nil, err
		}
		return secured, nil
	}
	return nil, fail("The server chose a login WebTerm does not support.")
}

// choose picks the strongest login we can do from what the server offers.
func choose(types []uint32, a Auth) (int, error) {
	offers := map[uint32]bool{}
	for _, t := range types {
		offers[t] = true
	}
	switch {
	case offers[secVeNCrypt]:
		return secVeNCrypt, nil
	case offers[secVNC] && a.Password != "":
		return secVNC, nil
	case offers[secNone]:
		return secNone, nil
	case offers[secVNC]:
		return 0, fail("This server asks for a password. Edit the host and enter it.")
	}
	return 0, fail("This server only offers logins WebTerm does not support yet: RealVNC's own encrypted login, or RSA-AES. In RealVNC Server, set Authentication to “VNC password”. In wayvnc, set a TLS certificate (private_key_file and certificate_file) so it offers a username and password login.")
}

type hs struct {
	conn net.Conn
	to   time.Duration
}

func (h *hs) read(n int) ([]byte, error) {
	buf := make([]byte, n)
	h.conn.SetReadDeadline(time.Now().Add(h.to))
	if _, err := io.ReadFull(h.conn, buf); err != nil {
		return nil, fail("The VNC server closed the connection during the login.")
	}
	return buf, nil
}

func (h *hs) write(b []byte) error {
	h.conn.SetWriteDeadline(time.Now().Add(h.to))
	if _, err := h.conn.Write(b); err != nil {
		return fail("The VNC server closed the connection during the login.")
	}
	return nil
}

func (h *hs) u32() (uint32, error) {
	b, err := h.read(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// reason reads the text a server sends with a failure.
func (h *hs) reason() string {
	n, err := h.u32()
	if err != nil || n == 0 || n > 4096 {
		return ""
	}
	b, err := h.read(int(n))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// version agrees on a protocol version, 3, 7 or 8 for 3.3, 3.7 and 3.8.
func (h *hs) version() (int, error) {
	b, err := h.read(12)
	if err != nil {
		return 0, err
	}
	s := string(b)
	if !strings.HasPrefix(s, "RFB ") || s[7] != '.' || s[11] != '\n' {
		return 0, fail("That address does not speak VNC. Check the host and port (VNC is usually on 5900).")
	}
	major, e1 := strconv.Atoi(s[4:7])
	minor, e2 := strconv.Atoi(s[8:11])
	if e1 != nil || e2 != nil || major != 3 {
		return 0, fail("This VNC server uses a protocol version WebTerm does not know (%q).", strings.TrimSpace(s))
	}
	v := 3
	switch {
	case minor >= 8:
		v = 8
	case minor == 7:
		v = 7
	}
	return v, h.write([]byte(fmt.Sprintf("RFB 003.%03d\n", map[int]int{3: 3, 7: 7, 8: 8}[v])))
}

func (h *hs) securityTypes(ver int) ([]uint32, error) {
	if ver == 3 { // the server decides
		t, err := h.u32()
		if err != nil {
			return nil, err
		}
		if t == 0 {
			return nil, h.failed("The VNC server refused the connection")
		}
		return []uint32{t}, nil
	}
	b, err := h.read(1)
	if err != nil {
		return nil, err
	}
	if b[0] == 0 {
		return nil, h.failed("The VNC server refused the connection")
	}
	list, err := h.read(int(b[0]))
	if err != nil {
		return nil, err
	}
	out := make([]uint32, len(list))
	for i, t := range list {
		out[i] = uint32(t)
	}
	return out, nil
}

func (h *hs) failed(prefix string) error {
	if r := h.reason(); r != "" {
		return fail("%s: %s", prefix, r)
	}
	return fail("%s.", prefix)
}

// result reads the server's verdict on the login.
func (h *hs) result(ver int) error {
	r, err := h.u32()
	if err != nil {
		return err
	}
	if r == 0 {
		return nil
	}
	reason := ""
	if ver >= 8 {
		reason = h.reason()
	}
	if reason == "" {
		reason = "wrong password"
	}
	return fail("The VNC server rejected the login: %s.", reason)
}

// vncAuth answers a VNC password challenge.
func (h *hs) vncAuth(password string) error {
	challenge, err := h.read(16)
	if err != nil {
		return err
	}
	resp, err := VNCResponse(challenge, password)
	if err != nil {
		return err
	}
	return h.write(resp)
}

// VNCResponse is the challenge encrypted with DES, keyed by the password: its first eight characters,
// each byte with its bits reversed, as the protocol defines.
func VNCResponse(challenge []byte, password string) ([]byte, error) {
	key := make([]byte, 8)
	copy(key, password)
	for i, b := range key {
		var r byte
		for bit := 0; bit < 8; bit++ {
			r |= (b >> bit & 1) << (7 - bit)
		}
		key[i] = r
	}
	c, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	c.Encrypt(out[:8], challenge[:8])
	c.Encrypt(out[8:], challenge[8:])
	return out, nil
}

// vencrypt runs the VeNCrypt login: agree on a version and a sub-type, move to TLS, and then log in
// inside the TLS connection.
func (h *hs) vencrypt(a Auth) (net.Conn, error) {
	v, err := h.read(2)
	if err != nil {
		return nil, err
	}
	if v[0] != 0 || v[1] < 2 {
		return nil, fail("The server's TLS login version is too old for WebTerm.")
	}
	if err := h.write([]byte{0, 2}); err != nil {
		return nil, err
	}
	if ack, err := h.read(1); err != nil || ack[0] != 0 {
		return nil, fail("The server would not use the TLS login version WebTerm offered.")
	}
	n, err := h.read(1)
	if err != nil {
		return nil, err
	}
	raw, err := h.read(int(n[0]) * 4)
	if err != nil {
		return nil, err
	}
	offers := map[uint32]bool{}
	for i := 0; i < int(n[0]); i++ {
		offers[binary.BigEndian.Uint32(raw[i*4:])] = true
	}
	sub, err := chooseVeNCrypt(offers, a)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, sub)
	if err := h.write(b); err != nil {
		return nil, err
	}
	if ack, err := h.read(1); err != nil || ack[0] != 1 {
		return nil, fail("The server would not use that TLS login.")
	}

	tlsConn := tls.Client(h.conn, &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- the certificate is checked against the pinned one just below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return fail("The server did not present a certificate.")
			}
			if a.VerifyCert != nil {
				// Deciding can take as long as a person needs, so the handshake's clock starts again afterwards.
				defer h.conn.SetDeadline(time.Now().Add(h.to))
				return a.VerifyCert(raw[0])
			}
			return nil
		},
	})
	h.conn.SetDeadline(time.Now().Add(h.to))
	if err := tlsConn.Handshake(); err != nil {
		var e *Error
		if errors.As(err, &e) {
			return nil, e
		}
		return nil, fail("The TLS connection to the VNC server failed: %v", err)
	}
	h.conn.SetDeadline(time.Time{})
	th := &hs{conn: tlsConn, to: h.to}

	switch sub {
	case vencryptX509Plain:
		u, p := []byte(a.Username), []byte(a.Password)
		msg := make([]byte, 8, 8+len(u)+len(p))
		binary.BigEndian.PutUint32(msg, uint32(len(u)))
		binary.BigEndian.PutUint32(msg[4:], uint32(len(p)))
		if err := th.write(append(append(msg, u...), p...)); err != nil {
			return nil, err
		}
	case vencryptX509Vnc:
		if err := th.vncAuth(a.Password); err != nil {
			return nil, err
		}
	}
	// A login always gets a verdict after VeNCrypt, and a failure comes with a reason (RFB 3.8).
	return tlsConn, th.result(8)
}

func chooseVeNCrypt(offers map[uint32]bool, a Auth) (uint32, error) {
	switch {
	case offers[vencryptX509Plain] && a.Username != "":
		return vencryptX509Plain, nil
	case offers[vencryptX509Vnc] && a.Password != "":
		return vencryptX509Vnc, nil
	case offers[vencryptX509None] && a.Password == "" && a.Username == "":
		return vencryptX509None, nil
	case offers[vencryptX509Plain]:
		return 0, fail("This server asks for a username and password. Edit the host and enter the username too.")
	case offers[vencryptX509Vnc]:
		return 0, fail("This server asks for a password. Edit the host and enter it.")
	}
	return 0, fail("This server only offers a TLS login WebTerm cannot use (one without a certificate), or none it can use. Turn on certificate-based login on the server.")
}

// ServeBrowser plays the server's part of the handshake for the browser's noVNC, offering no login,
// because WebTerm has already logged in. When it returns, the next bytes are the client's ClientInit.
func ServeBrowser(rw io.ReadWriter) error {
	if _, err := rw.Write([]byte("RFB 003.008\n")); err != nil {
		return err
	}
	v := make([]byte, 12)
	if _, err := io.ReadFull(rw, v); err != nil {
		return err
	}
	if !strings.HasPrefix(string(v), "RFB 003.00") || (v[10] != '8' && v[10] != '7') {
		return errors.New("the browser's VNC client speaks a version this proxy does not")
	}
	if _, err := rw.Write([]byte{1, secNone}); err != nil {
		return err
	}
	sel := make([]byte, 1)
	if _, err := io.ReadFull(rw, sel); err != nil {
		return err
	}
	if sel[0] != secNone {
		return errors.New("the browser's VNC client chose a login this proxy did not offer")
	}
	if v[10] == '8' { // 3.7 sends no result for no login
		_, err := rw.Write([]byte{0, 0, 0, 0})
		return err
	}
	return nil
}
