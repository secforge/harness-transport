package codexmsg

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
)

// fakeDaemon is a stand-in app server: it accepts the upgrade the way
// tokio-tungstenite's accept_hdr_async does, then answers requests from a
// table. The handshake is written independently of the client's own code so
// the test does not simply agree with itself.
type fakeDaemon struct {
	t       *testing.T
	path    string
	ln      net.Listener
	handler func(method string, params json.RawMessage) (any, *Error)
	// notify, when set, is sent as a notification before the first response.
	notify string
}

func startFakeDaemon(t *testing.T, handler func(string, json.RawMessage) (any, *Error)) *fakeDaemon {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "app-server-control.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("cannot bind a unix socket here: %v", err)
	}
	d := &fakeDaemon{t: t, path: path, ln: ln, handler: handler}
	t.Cleanup(func() { ln.Close() })
	go d.serve()
	return d
}

func (d *fakeDaemon) serve() {
	for {
		conn, err := d.ln.Accept()
		if err != nil {
			return
		}
		go d.handle(conn)
	}
}

func (d *fakeDaemon) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	h := sha1.New()
	io.WriteString(h, req.Header.Get("Sec-WebSocket-Key")+wsGUID)
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)

	ws := &wsConn{conn: conn, br: br}
	if d.notify != "" {
		ws.writeFrame(opText, []byte(fmt.Sprintf(`{"method":%q,"params":{"hello":true}}`, d.notify)))
	}
	for {
		data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		var r struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(data, &r); err != nil {
			return
		}
		// A real app server carries no "jsonrpc" member; a client that sends
		// one is speaking a different dialect.
		if strings.Contains(string(data), `"jsonrpc"`) {
			d.t.Errorf("client sent a jsonrpc member, which this protocol does not use: %s", data)
		}
		result, rpcErr := d.handler(r.Method, r.Params)
		var resp []byte
		if rpcErr != nil {
			resp, _ = json.Marshal(map[string]any{"id": json.RawMessage(r.ID), "error": rpcErr})
		} else {
			resp, _ = json.Marshal(map[string]any{"id": json.RawMessage(r.ID), "result": result})
		}
		if err := ws.writeFrame(opText, resp); err != nil {
			return
		}
	}
}

func dialFake(t *testing.T, d *fakeDaemon) *Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, Options{SocketPath: d.path})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestInitializeAndListThreads(t *testing.T) {
	d := startFakeDaemon(t, func(method string, params json.RawMessage) (any, *Error) {
		switch method {
		case MethodInitialize:
			var p InitializeParams
			json.Unmarshal(params, &p)
			if p.ClientInfo.Name == "" {
				return nil, &Error{Code: CodeInvalidRequest, Message: "no client name"}
			}
			return map[string]any{"userAgent": "fake/1"}, nil
		case MethodThreadList:
			return ThreadListResult{Threads: []Thread{
				{ID: "0199a1f4-0000-7000-8000-000000000001", Name: "alpha", Cwd: "/tmp"},
				{ID: "0199a1f4-0000-7000-8000-000000000002", Name: "beta"},
			}}, nil
		}
		return nil, &Error{Code: CodeMethodNotFound, Message: "unknown method " + method}
	})

	c := dialFake(t, d)
	ctx := context.Background()
	if _, err := c.Initialize(ctx, InitializeParams{
		ClientInfo: ClientInfo{Name: "codexmsg-test", Version: "0.1.0"},
	}); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	page, err := c.ListThreads(ctx, ThreadListParams{})
	if err != nil {
		t.Fatalf("thread/list: %v", err)
	}
	if len(page.Threads) != 2 || page.Threads[0].Name != "alpha" {
		t.Fatalf("threads = %+v", page.Threads)
	}
	if len(page.Threads[0].Raw) == 0 {
		t.Error("the undecoded record should be kept, since the server sends fields we do not model")
	}
}

// A name has to be resolved through thread/list; a UUID is used as given, so
// naming a thread by id must not cost a round trip.
func TestFindThreadByNameAndByID(t *testing.T) {
	listed := 0
	d := startFakeDaemon(t, func(method string, _ json.RawMessage) (any, *Error) {
		if method == MethodThreadList {
			listed++
			return ThreadListResult{Threads: []Thread{{ID: "id-1", Name: "beta"}}}, nil
		}
		return map[string]any{}, nil
	})
	c := dialFake(t, d)
	ctx := context.Background()

	got, err := c.FindThread(ctx, "beta")
	if err != nil || got.ID != "id-1" {
		t.Fatalf("FindThread(name) = %+v, %v", got, err)
	}
	uuid := NewUUIDv7()
	got, err = c.FindThread(ctx, uuid)
	if err != nil || got.ID != uuid {
		t.Fatalf("FindThread(uuid) = %+v, %v", got, err)
	}
	if listed != 1 {
		t.Errorf("thread/list called %d times; a UUID target should not need a listing", listed)
	}
}

func TestQueueMessageSendsTheCLIsShape(t *testing.T) {
	var got ThreadQueueAddParams
	d := startFakeDaemon(t, func(method string, params json.RawMessage) (any, *Error) {
		if method != MethodThreadQueueAdd {
			return nil, &Error{Code: CodeMethodNotFound, Message: method}
		}
		if err := json.Unmarshal(params, &got); err != nil {
			return nil, &Error{Code: CodeInvalidRequest, Message: err.Error()}
		}
		return ThreadQueueAddResult{QueuedSubmission: QueuedSubmission{ID: "sub-1"}}, nil
	})
	c := dialFake(t, d)

	res, err := c.QueueMessage(context.Background(), "thread-1", "hello there", "")
	if err != nil {
		t.Fatalf("QueueMessage: %v", err)
	}
	if res.QueuedSubmission.ID != "sub-1" {
		t.Errorf("queued submission = %+v", res.QueuedSubmission)
	}
	if got.ThreadID != "thread-1" || len(got.Input) != 1 {
		t.Fatalf("params = %+v", got)
	}
	if got.Input[0].Type != "text" || got.Input[0].Text != "hello there" {
		t.Errorf("input = %+v, want a text item", got.Input[0])
	}
	if got.Input[0].TextElements == nil {
		t.Error("text_elements must be present even when empty; the server requires the field")
	}
	if got.ClientUserMessageID == "" {
		t.Error("a client message id should be generated when none is given")
	}
}

// An older daemon rejects the method; the caller must be told that plainly
// rather than being left to guess from a bare JSON-RPC code.
func TestQueueMessageExplainsAnOldDaemon(t *testing.T) {
	d := startFakeDaemon(t, func(string, json.RawMessage) (any, *Error) {
		return nil, &Error{Code: CodeMethodNotFound, Message: "unknown"}
	})
	c := dialFake(t, d)
	_, err := c.QueueMessage(context.Background(), "t", "hi", "")
	if err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Errorf("error = %v, want it to name the unsupported method", err)
	}
}

func TestServerErrorsSurfaceWithTheirCode(t *testing.T) {
	d := startFakeDaemon(t, func(string, json.RawMessage) (any, *Error) {
		return nil, &Error{Code: CodeOverloaded, Message: "busy"}
	})
	c := dialFake(t, d)
	err := c.Call(context.Background(), "thread/read", map[string]string{"threadId": "x"}, nil)
	var rpc *Error
	if !asError(err, &rpc) {
		t.Fatalf("error = %v, want a *Error", err)
	}
	if rpc.Code != CodeOverloaded {
		t.Errorf("code = %d, want %d", rpc.Code, CodeOverloaded)
	}
	if IsMethodNotFound(err) {
		t.Error("overloaded should not be mistaken for an unknown method")
	}
}

func TestNotificationsAreDelivered(t *testing.T) {
	d := startFakeDaemon(t, func(string, json.RawMessage) (any, *Error) {
		return map[string]any{}, nil
	})
	d.notify = "thread/event"
	c := dialFake(t, d)
	// Any request forces the connection to be established and read.
	c.Call(context.Background(), MethodInitialize, InitializeParams{ClientInfo: ClientInfo{Name: "x", Version: "1"}}, nil)

	select {
	case m := <-c.Notifications():
		if m.Method != "thread/event" {
			t.Errorf("notification method = %q", m.Method)
		}
		if !m.IsNotification() || m.IsResponse() {
			t.Error("a frame with a method and no id is a notification")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no notification arrived")
	}
}

// A call in flight when the daemon goes away must fail, not hang.
func TestCallFailsWhenTheDaemonDisappears(t *testing.T) {
	d := startFakeDaemon(t, func(string, json.RawMessage) (any, *Error) {
		return map[string]any{}, nil
	})
	c := dialFake(t, d)
	d.ln.Close()
	c.ws.conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Call(ctx, MethodThreadList, ThreadListParams{}, nil); err == nil {
		t.Error("a call on a dead connection should fail")
	}
}

func TestDialRejectsAMissingSocket(t *testing.T) {
	_, err := Dial(context.Background(), Options{SocketPath: filepath.Join(t.TempDir(), "absent.sock")})
	if err == nil {
		t.Fatal("dialling an absent socket should fail")
	}
	if !strings.Contains(err.Error(), "no app-server daemon") {
		t.Errorf("error = %v, want it to explain that no daemon is running", err)
	}
}

// A Codex home deep enough to exceed the AF_UNIX limit does not fail loudly
// in the CLI — it silently uses an embedded server instead of the daemon. A
// client that cannot bind should at least say why.
func TestCheckSocketPathRejectsAnOverlongPath(t *testing.T) {
	long := filepath.Join("/tmp", strings.Repeat("d", 120), "app-server-control.sock")
	err := CheckSocketPath(long)
	if err == nil || !strings.Contains(err.Error(), "AF_UNIX limit") {
		t.Errorf("error = %v, want it to name the path limit", err)
	}
}

func TestHomeHonoursCodexHome(t *testing.T) {
	t.Setenv("CODEX_HOME", "/custom/codex")
	h, err := Home()
	if err != nil {
		t.Fatal(err)
	}
	if h != "/custom/codex" {
		t.Errorf("Home = %q", h)
	}
	if got, want := ControlSocketPath(h), "/custom/codex/app-server-control/app-server-control.sock"; got != want {
		t.Errorf("ControlSocketPath = %q, want %q", got, want)
	}
	os.Unsetenv("CODEX_HOME")
}
