package codexmsg

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// The vectors below are RFC 6455's own, so they check the codec against the
// specification rather than against itself.

func TestAcceptTokenMatchesRFC6455(t *testing.T) {
	// RFC 6455 §1.3.
	if got, want := wsAccept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="; got != want {
		t.Errorf("wsAccept = %q, want %q", got, want)
	}
}

func TestReadFrameDecodesMaskedHello(t *testing.T) {
	// RFC 6455 §5.7: a single-frame masked "Hello".
	frame := []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}
	w := &wsConn{br: bufio.NewReader(bytes.NewReader(frame))}
	op, payload, fin, err := w.readFrame()
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if op != opText || !fin || string(payload) != "Hello" {
		t.Errorf("op %#x fin %v payload %q, want text/true/\"Hello\"", op, fin, payload)
	}
}

func TestReadMessageReassemblesFragments(t *testing.T) {
	// RFC 6455 §5.7: "Hel" + "lo" as two unmasked fragments.
	frames := []byte{0x01, 0x03, 'H', 'e', 'l', 0x80, 0x02, 'l', 'o'}
	w := &wsConn{br: bufio.NewReader(bytes.NewReader(frames))}
	msg, err := w.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if string(msg) != "Hello" {
		t.Errorf("message = %q, want %q", msg, "Hello")
	}
}

// Every client frame must be masked, and the length must use the shortest
// form the length allows — a server is entitled to reject either.
func TestWriteFrameMasksAndSizesCorrectly(t *testing.T) {
	for _, tc := range []struct {
		n        int
		wantLen  byte
		wantHead int
	}{
		{5, 5, 2},
		{125, 125, 2},
		{126, 126, 4},
		{70000, 127, 10},
	} {
		var buf bytes.Buffer
		w := &wsConn{conn: nopConn{&buf}}
		payload := bytes.Repeat([]byte("x"), tc.n)
		if err := w.writeFrame(opText, payload); err != nil {
			t.Fatalf("writeFrame(%d): %v", tc.n, err)
		}
		out := buf.Bytes()
		if out[0] != 0x81 {
			t.Errorf("n=%d: first byte %#x, want FIN|text", tc.n, out[0])
		}
		if out[1]&0x80 == 0 {
			t.Errorf("n=%d: mask bit not set; a server must drop an unmasked client frame", tc.n)
		}
		if got := out[1] & 0x7f; got != tc.wantLen {
			t.Errorf("n=%d: length byte %d, want %d", tc.n, got, tc.wantLen)
		}
		// Header, then a 4-byte mask, then the payload.
		if want := tc.wantHead + 4 + tc.n; len(out) != want {
			t.Errorf("n=%d: wrote %d bytes, want %d", tc.n, len(out), want)
		}
		// Round-trip it back through the reader.
		r := &wsConn{br: bufio.NewReader(bytes.NewReader(out))}
		_, got, _, err := r.readFrame()
		if err != nil {
			t.Fatalf("n=%d: readFrame: %v", tc.n, err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("n=%d: payload did not survive masking", tc.n)
		}
	}
}

// A ping must be answered with a pong carrying the same payload, and must not
// surface as an application message.
func TestReadMessageAnswersPing(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	w := &wsConn{conn: client, br: bufio.NewReader(client)}
	go func() {
		// An unmasked ping, then a text message, as a server sends them.
		server.Write([]byte{0x89, 0x04, 'p', 'i', 'n', 'g'})
		server.Write([]byte{0x81, 0x02, 'h', 'i'})
	}()

	done := make(chan []byte, 1)
	errc := make(chan error, 1)
	go func() {
		msg, err := w.ReadMessage()
		if err != nil {
			errc <- err
			return
		}
		done <- msg
	}()

	// Read the pong the reader owes us.
	server.SetReadDeadline(time.Now().Add(5 * time.Second))
	head := make([]byte, 2)
	if _, err := io.ReadFull(server, head); err != nil {
		t.Fatalf("read pong header: %v", err)
	}
	if head[0]&0x0f != opPong {
		t.Errorf("opcode %#x, want pong", head[0]&0x0f)
	}
	body := make([]byte, int(head[1]&0x7f)+4) // masked: 4-byte key first
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatalf("read pong body: %v", err)
	}
	for i := 4; i < len(body); i++ {
		body[i] ^= body[(i-4)%4]
	}
	if string(body[4:]) != "ping" {
		t.Errorf("pong payload %q, want the ping's payload", body[4:])
	}

	select {
	case msg := <-done:
		if string(msg) != "hi" {
			t.Errorf("message = %q, want %q", msg, "hi")
		}
	case err := <-errc:
		t.Fatalf("ReadMessage: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("ReadMessage did not return the text frame after the ping")
	}
}

func TestReadFrameRejectsOversizedPayload(t *testing.T) {
	// A 127-length frame claiming more than the cap.
	frame := []byte{0x81, 127, 0xff, 0, 0, 0, 0, 0, 0, 0}
	w := &wsConn{br: bufio.NewReader(bytes.NewReader(frame))}
	if _, _, _, err := w.readFrame(); err == nil {
		t.Error("an oversized frame should be refused rather than allocated")
	}
}

// nopConn adapts a writer to net.Conn for the write-side tests.
type nopConn struct{ w io.Writer }

func (n nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (n nopConn) Write(b []byte) (int, error)      { return n.w.Write(b) }
func (n nopConn) Close() error                     { return nil }
func (n nopConn) LocalAddr() net.Addr              { return nil }
func (n nopConn) RemoteAddr() net.Addr             { return nil }
func (n nopConn) SetDeadline(time.Time) error      { return nil }
func (n nopConn) SetReadDeadline(time.Time) error  { return nil }
func (n nopConn) SetWriteDeadline(time.Time) error { return nil }
