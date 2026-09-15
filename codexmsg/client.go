package codexmsg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DialTimeout bounds the connect and upgrade.
const DialTimeout = 10 * time.Second

// Client is a connection to a Codex app-server daemon.
//
// Unlike Claude Code's mesh — a socket per session, peers addressing each
// other directly — Codex is a hub: one daemon owns every thread, and a client
// names a thread by id or by name. So there is one connection here, not one
// per correspondent, and it multiplexes.
type Client struct {
	ws     *wsConn
	nextID atomic.Int64

	writeMu sync.Mutex

	mu      sync.Mutex
	pending map[string]chan *Message
	closed  bool
	err     error

	notifications chan *Message
	serverReqs    chan *Message
	done          chan struct{}
}

// Options configure a connection.
type Options struct {
	// SocketPath overrides the discovered control socket.
	SocketPath string
	// Path is the WebSocket request target. Empty means "/".
	// "/daemon/shutdown" asks a managed daemon to stop and is refused by one
	// that is not managed, so it is never sent by default.
	Path string
	// NotificationBuffer sizes the channel served by Notifications. A full
	// channel drops the oldest notification rather than stalling the reader
	// loop, which would deadlock every in-flight call.
	NotificationBuffer int
}

// Dial connects to the daemon's control socket and performs the WebSocket
// upgrade. It does not initialize: call Initialize before anything else, as
// the app server expects that handshake first.
func Dial(ctx context.Context, opt Options) (*Client, error) {
	path := opt.SocketPath
	if path == "" {
		p, err := DefaultSocket()
		if err != nil {
			return nil, err
		}
		path = p
	} else if err := CheckSocketPath(path); err != nil {
		return nil, err
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(DialTimeout)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", path, err)
	}
	target := opt.Path
	if target == "" {
		target = "/"
	}
	// The Host header is required by the upgrade but meaningless over a unix
	// socket; the app server does not inspect it.
	ws, err := wsHandshake(conn, "localhost", target, deadline)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("websocket upgrade on %s: %w", path, err)
	}

	buf := opt.NotificationBuffer
	if buf <= 0 {
		buf = 256
	}
	c := &Client{
		ws:            ws,
		pending:       map[string]chan *Message{},
		notifications: make(chan *Message, buf),
		serverReqs:    make(chan *Message, 16),
		done:          make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
}

// Notifications returns the stream of server notifications — turn output,
// item deltas, session events. A notification arriving with nobody reading is
// dropped rather than blocking the connection.
func (c *Client) Notifications() <-chan *Message { return c.notifications }

// ServerRequests returns requests the server makes of us, such as approval
// prompts. Answer one with Respond; ignoring them leaves the server waiting.
func (c *Client) ServerRequests() <-chan *Message { return c.serverReqs }

// Done is closed when the connection ends. Err then says why.
func (c *Client) Done() <-chan struct{} { return c.done }

// Err returns the error that ended the connection, if any.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// readLoop demultiplexes everything the server sends.
func (c *Client) readLoop() {
	for {
		data, err := c.ws.ReadMessage()
		if err != nil {
			c.fail(err)
			return
		}
		var m Message
		if err := json.Unmarshal(data, &m); err != nil {
			// A frame we cannot parse is skipped, not fatal: one malformed
			// message should not strand every in-flight call.
			continue
		}
		switch {
		case m.IsResponse():
			c.mu.Lock()
			ch, ok := c.pending[m.ID.key()]
			delete(c.pending, m.ID.key())
			c.mu.Unlock()
			if ok {
				ch <- &m
			}
		case m.IsServerRequest():
			select {
			case c.serverReqs <- &m:
			default:
			}
		case m.IsNotification():
			select {
			case c.notifications <- &m:
			default:
				// Drop the oldest to make room: a slow consumer should lose
				// history, not wedge the connection.
				select {
				case <-c.notifications:
				default:
				}
				select {
				case c.notifications <- &m:
				default:
				}
			}
		}
	}
}

// fail records the terminating error and wakes everyone waiting.
func (c *Client) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	if c.err == nil && !errors.Is(err, io.EOF) {
		c.err = err
	}
	pending := c.pending
	c.pending = map[string]chan *Message{}
	c.mu.Unlock()

	for _, ch := range pending {
		close(ch)
	}
	close(c.done)
}

// Call sends a request and waits for its response, decoding the result into
// out when out is non-nil.
func (c *Client) Call(ctx context.Context, method string, params, out any) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("marshal params for %s: %w", method, err)
		}
		raw = b
	}
	id := IntID(c.nextID.Add(1))
	req := Request{ID: id, Method: method, Params: raw}
	line, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", method, err)
	}

	ch := make(chan *Message, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return c.closedErr()
	}
	c.pending[id.key()] = ch
	c.mu.Unlock()

	if err := c.write(line); err != nil {
		c.mu.Lock()
		delete(c.pending, id.key())
		c.mu.Unlock()
		return fmt.Errorf("send %s: %w", method, err)
	}

	select {
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id.key())
		c.mu.Unlock()
		return ctx.Err()
	case m, ok := <-ch:
		if !ok {
			return fmt.Errorf("%s: %w", method, c.closedErr())
		}
		if m.Error != nil {
			return m.Error
		}
		if out == nil || len(m.Result) == 0 {
			return nil
		}
		if err := json.Unmarshal(m.Result, out); err != nil {
			return fmt.Errorf("decode %s result: %w", method, err)
		}
		return nil
	}
}

// Notify sends a notification, which expects no response.
func (c *Client) Notify(method string, params any) error {
	msg := map[string]any{"method": method}
	if params != nil {
		msg["params"] = params
	}
	line, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return c.write(line)
}

// Respond answers a server request.
func (c *Client) Respond(id RequestID, result any, rpcErr *Error) error {
	msg := map[string]any{"id": id}
	if rpcErr != nil {
		msg["error"] = rpcErr
	} else {
		msg["result"] = result
	}
	line, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return c.write(line)
}

func (c *Client) write(line []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.WriteText(line)
}

func (c *Client) closedErr() error {
	if c.err != nil {
		return c.err
	}
	return errors.New("connection to the app server is closed")
}

// Close shuts the connection down.
func (c *Client) Close() error {
	c.mu.Lock()
	already := c.closed
	c.mu.Unlock()
	err := c.ws.Close()
	if !already {
		c.fail(io.EOF)
	}
	return err
}
