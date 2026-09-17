package codexmsg

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Method names. The daemon answers 99 requests; these are the two needed to
// push a message into a thread.
//
// thread/queue/add is absent from the checked-in schema for 0.154.0 even
// though the CLI sends it: the schema lags the Rust source.
const (
	MethodInitialize     = "initialize"
	MethodThreadQueueAdd = "thread/queue/add"
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

// ThreadQueueAddParams queues a message on an existing thread. Field names are
// camelCase on the wire though the Rust struct uses underscores — serde
// renames them, and thread_id earns "missing field `threadId`", a params
// error that reads like an unsupported method.
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

type ThreadQueueAddResult struct {
	QueuedSubmission QueuedSubmission `json:"queuedSubmission"`
}

// QueueMessage queues a text message for an existing thread — this protocol's
// nearest equivalent to a user frame. It joins the queue and does not start a
// turn. The daemon refuses the method unless Initialize asked for
// Capabilities.ExperimentalAPI.
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
