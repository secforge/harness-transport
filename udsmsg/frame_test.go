package udsmsg

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeUserFrame(t *testing.T) {
	line := []byte(`{"type":"user","msg_id":"ab12","from":"uds:/tmp/cc-socks/1.sock","from_mode":"prompting","message":{"role":"user","content":"hello"}}`)
	f, err := DecodeFrame(line)
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
	f, err := DecodeFrame([]byte(`{"type":"user"}`))
	if err != nil {
		t.Fatal(err)
	}
	if f.Text() != "" {
		t.Errorf("Text() = %q, want empty", f.Text())
	}
}

func TestDecodeControlFrames(t *testing.T) {
	cases := map[string]struct {
		line   string
		action string
		check  func(*Frame) bool
	}{
		"rename": {`{"type":"control","action":"rename","name":"x"}`, ActionRename,
			func(f *Frame) bool { return f.Name == "x" }},
		"status": {`{"type":"control","action":"peer_message_status","status":"expired","status_detail":"refused","orig_msg_id":"m1"}`,
			ActionPeerMessageStatus,
			func(f *Frame) bool {
				return f.Status == StatusExpired && f.StatusDetail == "refused" && f.OrigMsgID == "m1"
			}},
		"idle": {`{"type":"control","action":"peer_idle_notice","orig_msg_id":"m1","state":"idle","finished_at":1.5}`,
			ActionPeerIdleNotice,
			func(f *Frame) bool { return f.State == "idle" && f.FinishedAt != nil && *f.FinishedAt == 1.5 }},
		"yielded": {`{"type":"control","action":"artifact_replies_yielded","orig_msg_id":"m1","yielded":["a"],"refused":[]}`,
			ActionArtifactRepliesYielded,
			func(f *Frame) bool { return string(f.Yielded) == `["a"]` }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f, err := DecodeFrame([]byte(tc.line))
			if err != nil {
				t.Fatal(err)
			}
			if f.Action != tc.action {
				t.Fatalf("Action = %q, want %q", f.Action, tc.action)
			}
			if !tc.check(f) {
				t.Errorf("fields not decoded: %+v", f)
			}
		})
	}
}

func TestEncodeFrameOmitsEmptyFields(t *testing.T) {
	line, err := EncodeFrame(&Frame{Type: TypeUser, Message: &UserMessage{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(line); got != `{"type":"user","message":{"role":"user","content":"hi"}}`+"\n" {
		t.Errorf("encoded %q", got)
	}
}

func TestEncodeFrameRejectsOversizeLine(t *testing.T) {
	f := &Frame{Type: TypeUser, Message: &UserMessage{Role: "user", Content: strings.Repeat("x", MaxLineBytes)}}
	if _, err := EncodeFrame(f); err == nil {
		t.Fatal("want an error for a frame over the line cap")
	}
}

func TestDecodeFrameRejectsGarbage(t *testing.T) {
	if _, err := DecodeFrame([]byte("not json")); err == nil {
		t.Fatal("want a parse error")
	}
}

// A msg_id the receiver's validator rejects cannot be correlated: status and
// idle notices for it go unmatched, and nothing anywhere reports the problem.
// The 32-hex form belongs to Windows pipe names, not to message ids.
func TestNewMsgIDMatchesTheReceiversValidator(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := NewMsgID()
		if !MsgIDPattern.MatchString(id) {
			t.Fatalf("msg id %q would not be correlated by the receiver", id)
		}
		if seen[id] {
			t.Fatalf("duplicate msg id %q", id)
		}
		seen[id] = true
	}
	if MsgIDPattern.MatchString(strings.Repeat("a", 32)) {
		t.Error("32 hex should not satisfy the msg_id validator")
	}
}

func TestUnknownFieldsSurviveInRaw(t *testing.T) {
	line := []byte(`{"type":"control","action":"future_action","novel_field":{"deep":1}}`)
	f, err := DecodeFrame(line)
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

func TestSplitLines(t *testing.T) {
	lines, rest := splitLines([]byte("a\nbb\nccc"))
	if len(lines) != 2 || string(lines[0]) != "a" || string(lines[1]) != "bb" {
		t.Fatalf("lines = %q", lines)
	}
	if string(rest) != "ccc" {
		t.Errorf("rest = %q, want the partial tail", rest)
	}
}
