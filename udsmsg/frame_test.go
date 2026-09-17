package udsmsg

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeUserFrame(t *testing.T) {
	line := []byte(`{"type":"user","msg_id":"ab12","from":"uds:/tmp/cc-socks/1.sock","from_mode":"prompting","message":{"role":"user","content":"hello"}}`)
	f, err := decodeFrame(line)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeUser || f.Text() != "hello" || f.MsgID != "ab12" || f.FromMode != ModePrompting {
		t.Fatalf("decoded %+v", f)
	}
	if string(f.Raw) != string(line) {
		t.Errorf("Raw = %s, want the original line", f.Raw)
	}
}

func TestTextIsEmptyWithoutMessage(t *testing.T) {
	f, err := decodeFrame([]byte(`{"type":"user"}`))
	if err != nil {
		t.Fatal(err)
	}
	if f.Text() != "" {
		t.Errorf("Text() = %q, want empty", f.Text())
	}
}

// A frame this package does not model still decodes, carrying its type and
// the whole line in Raw. Nothing is invented for it and nothing is rejected:
// a caller that wants such a frame reads Raw.
func TestUnmodelledFramesSurviveDecoding(t *testing.T) {
	const line = `{"type":"control","action":"peer_message_status","orig_msg_id":"m1"}`
	f, err := decodeFrame([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != "control" {
		t.Errorf("Type = %q, want the type as received", f.Type)
	}
	if string(f.Raw) != line {
		t.Errorf("Raw = %s, want the line as received", f.Raw)
	}
}

func TestEncodeFrameOmitsEmptyFields(t *testing.T) {
	line, err := encodeFrame(&Frame{Type: TypeUser, Message: &UserMessage{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(line); got != `{"type":"user","message":{"role":"user","content":"hi"}}`+"\n" {
		t.Errorf("encoded %q", got)
	}
}

func TestEncodeFrameRejectsOversizeLine(t *testing.T) {
	f := &Frame{Type: TypeUser, Message: &UserMessage{Role: "user", Content: strings.Repeat("x", MaxLineBytes)}}
	if _, err := encodeFrame(f); err == nil {
		t.Fatal("want an error for a frame over the line cap")
	}
}

func TestDecodeFrameRejectsGarbage(t *testing.T) {
	if _, err := decodeFrame([]byte("not json")); err == nil {
		t.Fatal("want a parse error")
	}
}

// Sessions were observed sending an RFC-4122 UUID as msg_id, so that is the
// shape we generate. The 32-hex form that appears elsewhere in this protocol
// is a Windows pipe name, not a message id.
func TestNewMsgIDIsAUUID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := newMsgID()
		if !msgIDPattern.MatchString(id) {
			t.Fatalf("msg id %q is not the UUID shape sessions send", id)
		}
		if seen[id] {
			t.Fatalf("duplicate msg id %q", id)
		}
		seen[id] = true
	}
	if msgIDPattern.MatchString(strings.Repeat("a", 32)) {
		t.Error("32 hex is a pipe name, and should not pass as a msg_id")
	}
}

func TestUnknownFieldsSurviveInRaw(t *testing.T) {
	line := []byte(`{"type":"control","action":"future_action","novel_field":{"deep":1}}`)
	f, err := decodeFrame(line)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(f.Raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["novel_field"]; !ok {
		t.Error("novel_field lost; Raw should preserve the whole line")
	}
}
