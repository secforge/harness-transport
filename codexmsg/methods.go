package codexmsg

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Method names. The full surface is 99 requests; these are the ones a client
// that wants to find a session and talk to it needs.
//
// MethodThreadQueueAdd is not in the checked-in JSON schema for 0.154.0 even
// though the CLI sends it — the schema lags the Rust source, so the schema is
// not a complete list of what a daemon answers. The CLI treats
// method-not-found on it as "this daemon is too old" and says so rather than
// silently doing something else; QueueMessage reports it the same way.
const (
	MethodInitialize       = "initialize"
	MethodThreadList       = "thread/list"
	MethodThreadRead       = "thread/read"
	MethodThreadStart      = "thread/start"
	MethodThreadResume     = "thread/resume"
	MethodThreadQueueAdd   = "thread/queue/add"
	MethodThreadInjectItem = "thread/inject_items"
	MethodTurnStart        = "turn/start"
	MethodTurnSteer        = "turn/steer"
	MethodTurnInterrupt    = "turn/interrupt"
	MethodLoadedThreadList = "thread/loaded/list"
)

// ClientInfo identifies this client to the app server. The name is recorded
// in thread metadata, so it shows up in thread/list and thread/read.
type ClientInfo struct {
	Name    string  `json:"name"`
	Title   *string `json:"title,omitempty"`
	Version string  `json:"version"`
}

// Capabilities are negotiated at initialize.
type Capabilities struct {
	// ExperimentalAPI opts into experimental methods and fields. Some
	// methods are refused without it.
	ExperimentalAPI bool `json:"experimentalApi,omitempty"`
}

// InitializeParams is the opening handshake.
type InitializeParams struct {
	ClientInfo   ClientInfo    `json:"clientInfo"`
	Capabilities *Capabilities `json:"capabilities,omitempty"`
}

// Initialize performs the handshake the app server expects before any other
// request. The raw result is returned undecoded: it carries server info whose
// shape varies by version, and guessing at it would age worse than handing it
// over.
func (c *Client) Initialize(ctx context.Context, p InitializeParams) (json.RawMessage, error) {
	if p.ClientInfo.Name == "" {
		return nil, fmt.Errorf("initialize needs a client name")
	}
	if p.ClientInfo.Version == "" {
		p.ClientInfo.Version = "0.0.0"
	}
	var out json.RawMessage
	if err := c.Call(ctx, MethodInitialize, p, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ThreadListParams filters and pages thread/list.
type ThreadListParams struct {
	// Archived returns only archived threads when true; only live ones when
	// false or unset.
	Archived *bool `json:"archived,omitempty"`
	// Cursor continues a previous page.
	Cursor *string `json:"cursor,omitempty"`
	// Limit is the page size.
	Limit *int `json:"limit,omitempty"`
	// Cwd restricts to threads whose session cwd matches exactly.
	Cwd any `json:"cwd,omitempty"`
}

// Thread is one session as the daemon reports it. The record carries far more
// than this — model, provider, git info, rollout path, section, turns — and it
// varies by version, so Raw keeps the whole thing.
type Thread struct {
	ID        string `json:"id"`
	SessionID string `json:"sessionId,omitempty"`
	Name      string `json:"name,omitempty"`
	Cwd       string `json:"cwd,omitempty"`
	Preview   string `json:"preview,omitempty"`
	// CreatedAt, UpdatedAt and RecencyAt are unix seconds, not strings.
	CreatedAt int64 `json:"createdAt,omitempty"`
	UpdatedAt int64 `json:"updatedAt,omitempty"`
	RecencyAt int64 `json:"recencyAt,omitempty"`
	// Status reports whether the thread is loaded; {"type":"notLoaded"} for
	// a session that exists on disk but has no runtime attached.
	Status     ThreadStatus    `json:"status,omitempty"`
	Path       string          `json:"path,omitempty"`
	Model      string          `json:"model,omitempty"`
	Originator string          `json:"originator,omitempty"`
	CLIVersion string          `json:"cliVersion,omitempty"`
	Ephemeral  bool            `json:"ephemeral,omitempty"`
	Archived   bool            `json:"archived,omitempty"`
	Raw        json.RawMessage `json:"-"`
}

// ThreadStatus is a thread's runtime state.
type ThreadStatus struct {
	Type string `json:"type"`
}

// Loaded reports whether a runtime is attached to the thread. A thread that
// is not loaded exists only as a rollout file on disk.
func (t *Thread) Loaded() bool { return t.Status.Type != "" && t.Status.Type != "notLoaded" }

// UnmarshalJSON keeps the undecoded record alongside the fields we model.
func (t *Thread) UnmarshalJSON(b []byte) error {
	type alias Thread
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*t = Thread(a)
	t.Raw = append(json.RawMessage(nil), b...)
	return nil
}

// ThreadListResult is a page of threads. The daemon returns the page under
// "data", and sends a nextCursor even when the page itself is empty, so an
// empty page does not mean the listing is finished.
type ThreadListResult struct {
	Threads    []Thread `json:"data"`
	NextCursor *string  `json:"nextCursor,omitempty"`
}

// ListThreads returns one page of threads.
func (c *Client) ListThreads(ctx context.Context, p ThreadListParams) (*ThreadListResult, error) {
	var out ThreadListResult
	if err := c.Call(ctx, MethodThreadList, p, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FindThread resolves a thread by id or by exact name, the way the CLI's
// --thread argument does. An id is used as given; anything else is matched
// against thread names.
func (c *Client) FindThread(ctx context.Context, target string) (*Thread, error) {
	if looksLikeUUID(target) {
		return &Thread{ID: target}, nil
	}
	var cursor *string
	// The daemon returns a cursor even for an empty page, so "no results" is
	// not a stop condition and a repeated cursor is the only reliable end.
	const maxPages = 100
	for page := 0; page < maxPages; page++ {
		res, err := c.ListThreads(ctx, ThreadListParams{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for i := range res.Threads {
			if res.Threads[i].Name == target {
				return &res.Threads[i], nil
			}
		}
		if res.NextCursor == nil || *res.NextCursor == "" {
			break
		}
		if cursor != nil && *cursor == *res.NextCursor {
			break // the cursor stopped advancing; there is nothing more
		}
		cursor = res.NextCursor
	}
	return nil, fmt.Errorf("no thread found matching %q", target)
}

// UserInput is one item of a message to a thread.
type UserInput struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
	// TextElements are UI spans within Text. The field is required by the
	// server even when empty, so it is not omitted.
	TextElements []any `json:"text_elements"`
}

// TextInput builds a plain text input item.
func TextInput(text string) UserInput {
	return UserInput{Type: "text", Text: text, TextElements: []any{}}
}

// ThreadQueueAddParams queues a message on an existing thread.
//
// The field names are camelCase on the wire even though the Rust struct
// declares them with underscores: serde renames them. Sending thread_id gets
// "Invalid request: missing field `threadId`" — which is a params error, not
// an unsupported method, however much it looks like one.
type ThreadQueueAddParams struct {
	ThreadID string      `json:"threadId"`
	Input    []UserInput `json:"input"`
	// ClientUserMessageID lets the caller correlate the queued message with
	// what comes back. The CLI sends a UUIDv7.
	ClientUserMessageID string `json:"clientUserMessageId"`
}

// QueuedSubmission is what the daemon queued, echoed back.
type QueuedSubmission struct {
	ID                  string      `json:"id"`
	Input               []UserInput `json:"input,omitempty"`
	ClientUserMessageID string      `json:"clientUserMessageId,omitempty"`
}

// ThreadQueueAddResult is the response to a queue add.
type ThreadQueueAddResult struct {
	QueuedSubmission QueuedSubmission `json:"queuedSubmission"`
}

// QueueMessage queues a text message for an existing thread — the equivalent
// of `codex queue --thread <t> --message <text>`, and the closest thing in
// this protocol to claude-send's user frame.
//
// The message joins the thread's queue; it does not start a turn on its own
// if the session is idle. Use StartTurn for that.
//
// The daemon refuses this method unless the connection was initialized with
// Capabilities.ExperimentalAPI, so Initialize must have asked for it.
func (c *Client) QueueMessage(ctx context.Context, threadID, text, clientMessageID string) (*ThreadQueueAddResult, error) {
	if clientMessageID == "" {
		clientMessageID = NewUUIDv7()
	}
	var out ThreadQueueAddResult
	err := c.Call(ctx, MethodThreadQueueAdd, ThreadQueueAddParams{
		ThreadID:            threadID,
		Input:               []UserInput{TextInput(text)},
		ClientUserMessageID: clientMessageID,
	}, &out)
	switch {
	case err == nil:
		return &out, nil
	case IsMethodNotFound(err):
		return nil, fmt.Errorf("the app-server daemon does not support %s; update or restart it: %w",
			MethodThreadQueueAdd, err)
	case strings.Contains(err.Error(), "experimentalApi"):
		return nil, fmt.Errorf("%s needs the experimentalApi capability: initialize with "+
			"Capabilities{ExperimentalAPI: true}: %w", MethodThreadQueueAdd, err)
	default:
		return nil, err
	}
}

// TurnStartParams starts a turn on a thread.
type TurnStartParams struct {
	ThreadID            string      `json:"threadId"`
	Input               []UserInput `json:"input,omitempty"`
	ClientUserMessageID *string     `json:"clientUserMessageId,omitempty"`
	Cwd                 *string     `json:"cwd,omitempty"`
}

// StartTurn sends input and starts a turn, rather than only queueing it.
func (c *Client) StartTurn(ctx context.Context, p TurnStartParams) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.Call(ctx, MethodTurnStart, p, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// InterruptTurn stops the running turn on a thread.
func (c *Client) InterruptTurn(ctx context.Context, threadID string) error {
	return c.Call(ctx, MethodTurnInterrupt, map[string]string{"threadId": threadID}, nil)
}

// SteerTurn redirects a turn that is already running.
func (c *Client) SteerTurn(ctx context.Context, threadID string, input []UserInput) error {
	return c.Call(ctx, MethodTurnSteer, map[string]any{
		"threadId": threadID,
		"input":    input,
	}, nil)
}

// looksLikeUUID reports whether s has the canonical UUID shape.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
