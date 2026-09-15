package codexmsg

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// A minimal RFC 6455 client, enough to speak to the app server and no more.
//
// The daemon frames its unix socket with WebSocket (tokio-tungstenite), not
// with the newline-delimited JSON the stdio and TCP transports use, so a raw
// socket write is not understood. Only the client half is implemented, and
// only the parts the app server exercises: a text frame per JSON-RPC message,
// continuation frames on read, ping/pong, and close.
//
// This is deliberately dependency-free, like the rest of this module: pulling
// a WebSocket library in for one handshake and one frame codec would cost more
// than it saves.

// wsGUID is the constant RFC 6455 appends to the client key before hashing.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Opcodes.
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// maxFrame caps a single incoming payload. The app server's messages are
// small; a larger one means something is wrong, and reading it would let a
// peer allocate arbitrarily.
const maxFrame = 16 << 20

// wsConn is a WebSocket connection over any stream. It is not safe for
// concurrent writes; Client serialises them.
type wsConn struct {
	conn net.Conn
	br   *bufio.Reader
}

// wsAccept computes the Sec-WebSocket-Accept value for a client key.
func wsAccept(key string) string {
	h := sha1.New()
	io.WriteString(h, key+wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsHandshake performs the client upgrade over an established connection.
// path is the request target: the app server routes "/daemon/shutdown"
// specially and treats everything else as an ordinary control connection.
func wsHandshake(conn net.Conn, host, path string, deadline time.Time) (*wsConn, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate websocket key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])

	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, fmt.Errorf("send upgrade request: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("read upgrade response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("upgrade refused: %s", resp.Status)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("upgrade response is not a websocket: %q", resp.Header.Get("Upgrade"))
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != wsAccept(key) {
		return nil, fmt.Errorf("upgrade response has the wrong accept token")
	}
	if !deadline.IsZero() {
		_ = conn.SetDeadline(time.Time{})
	}
	return &wsConn{conn: conn, br: br}, nil
}

// writeFrame writes one complete frame. A client must mask every frame it
// sends; a server that receives an unmasked frame is required to close the
// connection.
func (w *wsConn) writeFrame(opcode byte, payload []byte) error {
	var head [14]byte
	head[0] = 0x80 | opcode // FIN set: every frame we send is complete
	n := 2
	switch {
	case len(payload) < 126:
		head[1] = byte(len(payload))
	case len(payload) <= 0xFFFF:
		head[1] = 126
		binary.BigEndian.PutUint16(head[2:], uint16(len(payload)))
		n = 4
	default:
		head[1] = 127
		binary.BigEndian.PutUint64(head[2:], uint64(len(payload)))
		n = 10
	}
	head[1] |= 0x80 // mask bit

	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return fmt.Errorf("generate mask: %w", err)
	}
	copy(head[n:], mask[:])
	n += 4

	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	if _, err := w.conn.Write(head[:n]); err != nil {
		return err
	}
	if len(masked) == 0 {
		return nil
	}
	_, err := w.conn.Write(masked)
	return err
}

// WriteText sends one text frame.
func (w *wsConn) WriteText(payload []byte) error { return w.writeFrame(opText, payload) }

// readFrame reads one frame, returning its opcode, payload and FIN bit. A
// server frame is never masked, but an unmasked one is tolerated on read: we
// are a client, and rejecting it would gain nothing.
func (w *wsConn) readFrame() (opcode byte, payload []byte, fin bool, err error) {
	var head [2]byte
	if _, err := io.ReadFull(w.br, head[:]); err != nil {
		return 0, nil, false, err
	}
	fin = head[0]&0x80 != 0
	opcode = head[0] & 0x0F
	masked := head[1]&0x80 != 0
	length := uint64(head[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(w.br, ext[:]); err != nil {
			return 0, nil, false, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(w.br, ext[:]); err != nil {
			return 0, nil, false, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > maxFrame {
		return 0, nil, false, fmt.Errorf("frame of %d bytes is over the %d byte cap", length, maxFrame)
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(w.br, mask[:]); err != nil {
			return 0, nil, false, err
		}
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(w.br, payload); err != nil {
		return 0, nil, false, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, fin, nil
}

// ReadMessage returns the next complete application message, reassembling
// continuation frames and answering pings along the way. A close frame is
// reported as io.EOF once the courtesy close has been echoed.
func (w *wsConn) ReadMessage() ([]byte, error) {
	var buf []byte
	var msgOp byte
	for {
		op, payload, fin, err := w.readFrame()
		if err != nil {
			return nil, err
		}
		switch op {
		case opPing:
			if err := w.writeFrame(opPong, payload); err != nil {
				return nil, err
			}
			continue
		case opPong:
			continue
		case opClose:
			_ = w.writeFrame(opClose, payload)
			return nil, io.EOF
		case opText, opBinary:
			if len(buf) > 0 {
				return nil, fmt.Errorf("data frame arrived inside a fragmented message")
			}
			msgOp = op
			buf = payload
		case opContinuation:
			if msgOp == 0 {
				return nil, fmt.Errorf("continuation frame with nothing to continue")
			}
			buf = append(buf, payload...)
		default:
			return nil, fmt.Errorf("unknown opcode %#x", op)
		}
		if fin {
			return buf, nil
		}
	}
}

// Close sends a close frame and closes the underlying connection. The frame
// is best-effort: a peer that has already gone is not an error worth
// reporting over the close itself.
func (w *wsConn) Close() error {
	var status [2]byte
	binary.BigEndian.PutUint16(status[:], 1000) // normal closure
	_ = w.writeFrame(opClose, status[:])
	return w.conn.Close()
}
