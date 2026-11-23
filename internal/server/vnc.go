package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/thatguy-za/webterm/internal/crypto"
	"github.com/thatguy-za/webterm/internal/rfb"
)

// Wire protocol on /api/ws/vnc/{id}: text frames carry JSON control messages while WebTerm logs in
// to the VNC server (a host key prompt, an error, then "ready"). The browser answers "ready" with
// {"type":"attach"}, and from then on binary frames are the VNC (RFB) stream, which noVNC speaks.

// wsStream lets the browser's binary frames be read and written as a plain stream.
type wsStream struct {
	ctx context.Context
	c   *websocket.Conn
	in  chan []byte
	buf []byte
}

func (w *wsStream) Read(p []byte) (int, error) {
	for len(w.buf) == 0 {
		select {
		case b, ok := <-w.in:
			if !ok {
				return 0, io.EOF
			}
			w.buf = b
		case <-w.ctx.Done():
			return 0, w.ctx.Err()
		}
	}
	n := copy(p, w.buf)
	w.buf = w.buf[n:]
	return n, nil
}

func (w *wsStream) Write(p []byte) (int, error) {
	if err := w.c.Write(w.ctx, websocket.MessageBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *Server) handleVNC(w http.ResponseWriter, r *http.Request, a *authed) {
	host, err := s.db.GetHost(r.PathValue("id"), a.user.ID)
	if err != nil {
		apiErr(w, http.StatusNotFound, "not_found")
		return
	}
	if host.Protocol != "vnc" {
		apiErr(w, http.StatusBadRequest, "wrong_protocol")
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(1 << 20)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	go func() {
		t := time.NewTicker(wsPingEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				pctx, stop := context.WithTimeout(ctx, 10*time.Second)
				err := c.Ping(pctx)
				stop()
				if err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	send := func(m serverMsg) {
		b, _ := json.Marshal(m)
		c.Write(ctx, websocket.MessageText, b)
	}
	fail := func(msg string, retry bool) {
		send(serverMsg{Type: "error", Message: msg, Retry: retry})
		c.Close(websocket.StatusNormalClosure, "error")
	}

	trustCh := make(chan bool, 1)
	attachCh := make(chan struct{}, 1)
	stream := &wsStream{ctx: ctx, c: c, in: make(chan []byte, 256)}

	// Reader: control messages go to the steps that wait for them, binary frames to the stream. It also
	// ends the bridge if the web session has been signed out or has timed out.
	go func() {
		defer cancel()
		defer close(stream.in)
		for {
			typ, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			if _, ok := s.sess.get(a.token, s.cfg.SessionTimeout); !ok {
				c.Close(4401, "session ended")
				return
			}
			if typ == websocket.MessageBinary {
				select {
				case stream.in <- data:
				case <-ctx.Done():
					return
				}
				continue
			}
			var m clientMsg
			if json.Unmarshal(data, &m) != nil {
				continue
			}
			switch m.Type {
			case "trust":
				select {
				case trustCh <- m.Accept:
				default:
				}
			case "attach":
				select {
				case attachCh <- struct{}{}:
				default:
				}
			}
		}
	}()

	send(serverMsg{Type: "status", Message: "connecting"})

	raw, _, err := s.dialTCP(ctx, a.user.ID, host.Address, host.Port, 15*time.Second)
	if err != nil {
		fail("could not reach "+net.JoinHostPort(host.Address, strconv.Itoa(host.Port))+"."+s.tailnetHint(a.user.ID, host.Address), true)
		return
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()

	var password string
	if host.PasswordBlob != nil {
		pw, err := crypto.OpenSecret(s.master, a.sess.vk, host.ID, host.PasswordBlob)
		if err != nil {
			fail("The saved password could not be read. Edit the host and enter it again.", false)
			return
		}
		password = string(pw)
		crypto.Zero(pw)
	}

	conn, err := rfb.Login(raw, rfb.Auth{
		Username: host.Username, Password: password,
		VerifyCert: func(der []byte) error {
			sum := sha256.Sum256(der)
			fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
			if err := s.confirmFingerprint(ctx, host, "TLS certificate", fp, send, trustCh); err != nil {
				return &rfb.Error{Msg: "Connection cancelled: the server's certificate was not trusted."}
			}
			return nil
		},
	})
	password = ""
	if err != nil {
		var re *rfb.Error
		if errors.As(err, &re) {
			fail(re.Msg, false)
		} else {
			fail("Connection failed: "+err.Error(), true)
		}
		return
	}
	defer conn.Close()

	send(serverMsg{Type: "ready"})
	select {
	case <-attachCh:
	case <-time.After(30 * time.Second):
		return
	case <-ctx.Done():
		return
	}
	if err := rfb.ServeBrowser(stream); err != nil {
		return
	}

	// From here the two sides talk to each other, and WebTerm only carries the bytes.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer cancel()
		io.Copy(conn, stream)
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		io.Copy(stream, conn)
	}()
	wg.Wait()
	c.Close(websocket.StatusNormalClosure, "")
}
