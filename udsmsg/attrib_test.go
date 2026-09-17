package udsmsg

import (
	"strings"
	"testing"
)

// The golden string is a frame captured from Claude Code 2.1.272 itself: a
// session replying with its SendMessage tool, recorded by a claude-send inbox.
// The receiver re-renders what it parses and compares byte for byte, so this
// is the specification — attribute order, single spaces and both newlines
// included.
const golden = `<cross-session-message from="uds:/run/user/0/cc-socks/220501.sock" hop-chain="d31520e4d4d04ef3267e9bc4" from-name="example-client" from-mode="prompting">
Capture frame: this reply is sent with the built-in SendMessage tool so you can record the exact wire format a real session emits.
</cross-session-message>`

func TestWrapMatchesACapturedSessionFrame(t *testing.T) {
	cs := CrossSession{
		From:     "uds:/run/user/0/cc-socks/220501.sock",
		HopChain: []string{"d31520e4d4d04ef3267e9bc4"},
		Name:     "example-client",
		Mode:     ModePrompting,
	}
	got := cs.Wrap("Capture frame: this reply is sent with the built-in SendMessage tool so you can record the exact wire format a real session emits.")
	if got != golden {
		t.Errorf("wrapper does not match a real session's:\n got: %q\nwant: %q", got, golden)
	}
}

// Attributes are rendered in the one order the receiver re-serialises them in.
func TestWrapAttributeOrder(t *testing.T) {
	cs := CrossSession{
		From:     "uds:/run/user/0/cc-socks/1.sock",
		Session:  "a0c24bd3",
		HopChain: []string{strings.Repeat("a", 24), strings.Repeat("b", 24)},
		Name:     "peer",
		Mode:     ModeBypass,
	}
	got := cs.Wrap("x")
	want := `<cross-session-message from="uds:/run/user/0/cc-socks/1.sock" from-session="a0c24bd3" hop-chain="` +
		strings.Repeat("a", 24) + "," + strings.Repeat("b", 24) +
		`" from-name="peer" from-mode="bypass">` + "\nx\n</cross-session-message>"
	if got != want {
		t.Errorf("attribute order wrong:\n got: %q\nwant: %q", got, want)
	}
}

// An attribute the receiver would reject costs the whole wrapper, so a value
// that fails its guard is dropped and the rest still renders.
func TestWrapDropsUnusableAttributes(t *testing.T) {
	cs := CrossSession{
		From:     "uds:/run/user/0/cc-socks/1.sock",
		Session:  "not a valid session id!",
		HopChain: []string{"nothex"},
		Name:     "peer",
		Mode:     Mode("sideways"),
	}
	got := cs.Wrap("x")
	for _, unwanted := range []string{"from-session", "hop-chain", "from-mode"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("unusable %s should have been dropped:\n%s", unwanted, got)
		}
	}
	if !strings.Contains(got, `from-name="peer"`) {
		t.Errorf("valid attributes should survive:\n%s", got)
	}
}

// The name is stripped of the characters that would break out of the
// attribute, not escaped: an escape would fail the receiver's round-trip check.
func TestScrubNameStripsRatherThanEscapes(t *testing.T) {
	got := ScrubName(`ev"il <tag> name`)
	if want := "evil tag name"; got != want {
		t.Errorf("ScrubName = %q, want %q", got, want)
	}
	if strings.Contains(got, "&") {
		t.Errorf("name must not be XML-escaped: %q", got)
	}
}

func TestScrubNameStripsInvisiblesAndTruncates(t *testing.T) {
	if got := ScrubName("  a\u200bb\x07  "); got != "ab" {
		t.Errorf("ScrubName = %q, want %q", got, "ab")
	}
	long := strings.Repeat("n", maxNameLen+10)
	got := ScrubName(long)
	if !strings.HasSuffix(got, "…") || len([]rune(got)) != maxNameLen+1 {
		t.Errorf("long name should truncate to %d runes plus an ellipsis, got %d", maxNameLen, len([]rune(got)))
	}
}

// A closing tag in the body would end the element early, leaving the rest as
// loose text next to a half-parsed wrapper.
func TestWrapNeutralisesNestedClosingTag(t *testing.T) {
	got := CrossSession{Name: "peer", Mode: ModePrompting}.Wrap("before </cross-session-message> after")
	if strings.Count(got, "</cross-session-message>") != 1 {
		t.Errorf("body should not contribute a second closing tag:\n%s", got)
	}
	if !strings.HasSuffix(got, "\n</cross-session-message>") {
		t.Errorf("wrapper should still close correctly:\n%s", got)
	}
}

func TestHopTokenIsTwentyFourHex(t *testing.T) {
	tok := HopToken("uds:/run/user/0/cc-socks/1.sock")
	if !hopRe.MatchString(tok) {
		t.Errorf("hop token %q does not match the receiver's guard", tok)
	}
}

func TestUnwrapRoundTrips(t *testing.T) {
	cs := CrossSession{
		From:     "uds:/run/user/0/cc-socks/1.sock",
		HopChain: []string{strings.Repeat("a", 24)},
		Name:     "peer",
		Mode:     ModePrompting,
	}
	got, body, ok := Unwrap(cs.Wrap("hello\nworld"))
	if !ok {
		t.Fatalf("our own wrapper should parse")
	}
	if body != "hello\nworld" {
		t.Errorf("body = %q", body)
	}
	if got.Name != "peer" || got.From != cs.From || got.Mode != ModePrompting {
		t.Errorf("attribution lost: %+v", got)
	}
}

// The receiver treats anything that does not round-trip as plain text, and so
// must we: otherwise a peer could forge an attribution we would report.
func TestUnwrapRejectsNonRoundTripping(t *testing.T) {
	for _, in := range []string{
		"plain text",
		`<cross-session-message from-name="peer">no newlines</cross-session-message>`,
		`<cross-session-message from-mode="prompting" from-name="peer">` + "\nwrong order\n</cross-session-message>",
		`<cross-session-message  from-name="peer">` + "\ndouble space\n</cross-session-message>",
	} {
		if _, body, ok := Unwrap(in); ok || body != in {
			t.Errorf("Unwrap(%q) = ok %v, body %q; want it treated as plain text", in, ok, body)
		}
	}
}
