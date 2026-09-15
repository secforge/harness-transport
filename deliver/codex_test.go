package deliver

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secforge/harness-transport/codexmsg"
)

// fakeDaemon is a stand-in Codex app server: the WebSocket upgrade plus a
// JSON-RPC responder. It exists so the Codex path can be exercised without a
// live daemon and, more importantly, so the echo-verification path can be
// tested with a deliberately WRONG echo, which a real daemon will not produce.
type fakeDaemon struct {
	path string
	// mangleEcho rewrites the echoed text, to simulate a receipt that does
	// not match what was sent.
	mangleEcho func(string) string
	lastText   chan string
}

func startFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "app-server-control.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("cannot bind a unix socket here: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	d := &fakeDaemon{path: path, lastText: make(chan string, 4)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go d.handle(conn)
		}
	}()
	return d
}

func (d *fakeDaemon) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	h := sha1.New()
	io.WriteString(h, req.Header.Get("Sec-WebSocket-Key")+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
	fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(h.Sum(nil)))

	for {
		msg, err := readFrame(br)
		if err != nil {
			return
		}
		var r struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(msg, &r) != nil {
			return
		}
		var result any = map[string]any{}
		if r.Method == codexmsg.MethodThreadQueueAdd {
			var p codexmsg.ThreadQueueAddParams
			json.Unmarshal(r.Params, &p)
			text := ""
			if len(p.Input) > 0 {
				text = p.Input[0].Text
			}
			select {
			case d.lastText <- text:
			default:
			}
			echo := text
			if d.mangleEcho != nil {
				echo = d.mangleEcho(text)
			}
			result = map[string]any{"queuedSubmission": map[string]any{
				"id":    "sub-1",
				"input": []map[string]any{{"type": "text", "text": echo, "text_elements": []any{}}},
			}}
		}
		resp, _ := json.Marshal(map[string]any{"id": json.RawMessage(r.ID), "result": result})
		if writeFrame(conn, resp) != nil {
			return
		}
	}
}

// Minimal server-side framing: read a masked client frame, write an unmasked
// one. Only what the test needs.
func readFrame(br *bufio.Reader) ([]byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return nil, err
	}
	n := uint64(head[1] & 0x7f)
	switch n {
	case 126:
		ext := make([]byte, 2)
		io.ReadFull(br, ext)
		n = uint64(ext[0])<<8 | uint64(ext[1])
	case 127:
		ext := make([]byte, 8)
		io.ReadFull(br, ext)
		n = 0
		for _, b := range ext {
			n = n<<8 | uint64(b)
		}
	}
	var mask [4]byte
	if head[1]&0x80 != 0 {
		if _, err := io.ReadFull(br, mask[:]); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, err
	}
	if head[1]&0x80 != 0 {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return payload, nil
}

func writeFrame(w io.Writer, payload []byte) error {
	var head []byte
	switch {
	case len(payload) < 126:
		head = []byte{0x81, byte(len(payload))}
	case len(payload) <= 0xFFFF:
		head = []byte{0x81, 126, byte(len(payload) >> 8), byte(len(payload))}
	default:
		head = []byte{0x81, 127, 0, 0, 0, 0, byte(len(payload) >> 24), byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload))}
	}
	if _, err := w.Write(head); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// codexUnder points a Codex backend at a fake daemon by setting CODEX_HOME to
// the directory holding the socket's parent.
func codexUnder(t *testing.T, d *fakeDaemon) *codexBackend {
	t.Helper()
	// The backend resolves $CODEX_HOME/app-server-control/app-server-control.sock,
	// so stage the socket at that path.
	home := t.TempDir()
	dir := filepath.Join(home, "app-server-control")
	if err := mkdirAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := symlink(d.path, filepath.Join(dir, "app-server-control.sock")); err != nil {
		t.Skipf("cannot stage the control socket: %v", err)
	}
	t.Setenv("CODEX_HOME", home)
	return &codexBackend{}
}

func TestCodexDeliverVerifiesTheEcho(t *testing.T) {
	d := startFakeDaemon(t)
	c := codexUnder(t, d)
	if err := c.Adopt(map[string]any{"threadId": "thread-a"}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	defer c.Close()

	r, err := c.Deliver(context.Background(), Delivery{Cursor: "c-1", Body: "relayed content"})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if r.Observation != ObservedStored {
		t.Errorf("Observation = %v, want stored when the echo matches", r.Observation)
	}
	if !r.EchoVerified {
		t.Error("EchoVerified should be true when the daemon echoed the same bytes")
	}
	if r.Ref != "thread-a/sub-1" {
		t.Errorf("Ref = %q, want thread and submission for a later re-read", r.Ref)
	}
	select {
	case got := <-d.lastText:
		if !strings.Contains(got, "relayed content") || !strings.Contains(got, "c-1") {
			t.Errorf("the daemon received %q, want body and cursor", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the daemon received nothing")
	}
}

// A receipt that does not echo what was sent must not be reported as stored:
// acknowledgement and integrity fail independently, which is the whole reason
// EchoVerified exists.
func TestCodexReportsAMismatchedEchoHonestly(t *testing.T) {
	d := startFakeDaemon(t)
	d.mangleEcho = func(s string) string { return s[:len(s)/2] }
	c := codexUnder(t, d)
	c.Adopt(map[string]any{"threadId": "thread-a"})
	defer c.Close()

	r, err := c.Deliver(context.Background(), Delivery{Cursor: "c-1", Body: "relayed content"})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if r.Observation != ObservedAccepted {
		t.Errorf("Observation = %v, want accepted — acknowledged but not verified", r.Observation)
	}
	if r.EchoVerified {
		t.Error("EchoVerified must be false when the echo did not match")
	}
	if !strings.Contains(r.Detail, "re-read from the cursor") {
		t.Errorf("Detail should point at the cursor fallback: %q", r.Detail)
	}
}

func TestCodexRefusesOversize(t *testing.T) {
	d := startFakeDaemon(t)
	c := codexUnder(t, d)
	c.Adopt(map[string]any{"threadId": "thread-a"})
	defer c.Close()

	max, err := c.MaxIntactBytes()
	if err != nil {
		t.Fatal(err)
	}
	// The floor is a byte figure derived from a CHARACTER limit, so it sits
	// well under it — one character can be four bytes.
	if max <= 0 || max >= codexMaxChars {
		t.Fatalf("MaxIntactBytes = %d, want a margin under the daemon's %d", max, codexMaxChars)
	}

	// Refusal is decided on what the daemon counts, not on the floor.
	r, err := c.Deliver(context.Background(), Delivery{Cursor: "c", Body: strings.Repeat("x", codexMaxChars+1)})
	if err == nil {
		t.Fatal("a message over the daemon's character limit must be refused before it is sent")
	}
	if r.Truncated {
		t.Error("the message was refused, not truncated")
	}
	if !strings.Contains(err.Error(), "characters") {
		t.Errorf("the error should be stated in the units the daemon enforces: %v", err)
	}

	// ASCII well past the byte floor is fine, because the floor assumes
	// four bytes per character and ASCII spends one. Refusing it would be
	// safe and wrong.
	if ok, _, _ := c.Fits(Delivery{Body: strings.Repeat("x", max*3)}); !ok {
		t.Errorf("%d ASCII bytes should fit: the floor is not the limit", max*3)
	}

	// Multi-byte content is measured the way the daemon measures it. Four
	// bytes per character, at the floor, is exactly the worst case the
	// floor was derived for.
	if ok, _, _ := c.Fits(Delivery{Body: strings.Repeat("\U0001F600", max/4)}); !ok {
		t.Error("a body of four-byte characters at the floor should fit")
	}
}

// Small filesystem helpers, kept here so the test file is self-contained.
func mkdirAll(p string) error       { return os.MkdirAll(p, 0o700) }
func symlink(from, to string) error { return os.Symlink(from, to) }
