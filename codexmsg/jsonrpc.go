package codexmsg

import (
	"encoding/json"
	"fmt"
)

// The app server speaks a JSON-RPC dialect, not JSON-RPC 2.0: no frame carries
// a "jsonrpc" member. A request is {id, method, params?}, a response
// {id, result} or {id, error}. A generic client stamping "jsonrpc":"2.0" will
// not interoperate, which is why this is hand-rolled.

// RequestID is a request identifier: a string or an integer.
type RequestID struct {
	Num  int64
	Str  string
	IsID bool // distinguishes the zero value from id 0
}

// IntID returns a numeric request id.
func IntID(n int64) RequestID { return RequestID{Num: n, IsID: true} }

// MarshalJSON renders the id as the string or number it is. Without this a
// request carries an object where the server expects a scalar, and no response
// can be correlated with the call that asked for it.
func (r RequestID) MarshalJSON() ([]byte, error) {
	if r.Str != "" {
		return json.Marshal(r.Str)
	}
	return json.Marshal(r.Num)
}

func (r *RequestID) UnmarshalJSON(b []byte) error {
	r.IsID = true
	if len(b) > 0 && b[0] == '"' {
		return json.Unmarshal(b, &r.Str)
	}
	return json.Unmarshal(b, &r.Num)
}

// key is the map key used to correlate a response with its request.
func (r RequestID) key() string {
	if r.Str != "" {
		return "s:" + r.Str
	}
	return fmt.Sprintf("n:%d", r.Num)
}

// String renders the id for a message.
func (r RequestID) String() string {
	if r.Str != "" {
		return r.Str
	}
	return fmt.Sprintf("%d", r.Num)
}

// Request is a call that expects a response.
type Request struct {
	ID     RequestID       `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Message is any frame the server sends: a response, an error, a server-side
// request, or a notification. They are told apart by which fields are present.
type Message struct {
	ID     *RequestID      `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// IsResponse reports whether the message answers one of our requests.
func (m *Message) IsResponse() bool { return m.ID != nil && m.Method == "" }

// Error is a JSON-RPC error object.
type Error struct {
	Code    int64           `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string {
	if len(e.Data) > 0 {
		return fmt.Sprintf("app server error %d: %s (%s)", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("app server error %d: %s", e.Code, e.Message)
}

// JSON-RPC error codes the app server uses that a caller may want to branch
// on. MethodNotFound in particular means the daemon predates a method, which
// is a normal condition worth falling back from rather than failing on.
const (
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInternalError  = -32603
	CodeOverloaded     = -32001
)

// IsMethodNotFound reports the server rejecting a method it does not know.
// Only -32601 counts: -32600 is a malformed params object, and reading that
// as an unknown method turns "wrong field name" into "your daemon is old".
func IsMethodNotFound(err error) bool {
	var e *Error
	if !asError(err, &e) {
		return false
	}
	return e.Code == CodeMethodNotFound
}

// asError is errors.As specialised to *Error, kept here so jsonrpc.go has no
// dependency beyond encoding/json.
func asError(err error, target **Error) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
