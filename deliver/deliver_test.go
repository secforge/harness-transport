package deliver

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/secforge/harness-transport/udsmsg"
)

// Open picks the backend from the process relationship alone. Under a Claude
// session that is the inherited socket; with nothing inherited there is no
// parent to guess at.
func TestOpenSelectsTheParentThatLaunchedUs(t *testing.T) {
	t.Setenv(EnvClaudeSocket, "/run/user/0/cc-socks/4242.sock")
	t.Setenv(EnvClaudeToken, "cafebabe")
	if _, ok := Open().(*claudeBackend); !ok {
		t.Error("an inherited Claude socket should select the Claude backend")
	}

	t.Setenv(EnvClaudeSocket, "")
	t.Setenv(EnvClaudeToken, "")
	if _, ok := Open().(*codexBackend); !ok {
		t.Error("with no inherited Claude socket the Codex backend should be tried")
	}
}

// The cursor rides along with every message: a body that is lost or cut still
// leaves an anchor the model can re-fetch from.
func TestComposeAlwaysCarriesTheCursor(t *testing.T) {
	got := compose(Delivery{Cursor: "c-17", Body: "hello"})
	if !strings.Contains(got, "hello") || !strings.Contains(got, "c-17") {
		t.Errorf("compose = %q, want both body and cursor", got)
	}
	got = compose(Delivery{Cursor: "c-17", Body: "hello", More: true})
	if !strings.Contains(got, "more is waiting") {
		t.Errorf("compose = %q, want the more-waiting note", got)
	}
	// An empty body still delivers the anchor.
	if got := compose(Delivery{Cursor: "c-18"}); !strings.Contains(got, "c-18") {
		t.Errorf("compose = %q, want the cursor even with no body", got)
	}
}

// The trailer is an end marker: a caller distinguishes a complete delivery
// from one cut in transit by whether it is there. So it must be there on
// every delivery, including the ones that carry no cursor — a client's own
// notices, which are exactly the messages a reader cannot afford to treat as
// truncated.
func TestComposeAlwaysEndsWithATrailer(t *testing.T) {
	for _, d := range []Delivery{
		{Cursor: "c-1", Body: "x"},
		{Cursor: "c-1", Body: "x", More: true},
		{Body: "a notice with no anchor"},
		{Body: "a notice with no anchor", More: true},
		{Cursor: "c-1"},
		{},
	} {
		got := compose(d)
		if !strings.HasSuffix(got, "]") {
			t.Errorf("compose(%+v) = %q; every delivery must end with a trailer, or its absence "+
				"cannot mean truncation", d, got)
		}
		if d.Cursor == "" && !strings.Contains(got, "no cursor") {
			t.Errorf("compose(%+v) = %q; a delivery with no anchor should say so", d, got)
		}
		if d.More && !strings.Contains(got, "more is waiting") {
			t.Errorf("compose(%+v) = %q; the more flag was dropped", d, got)
		}
	}
}

func TestThreadIDFromMeta(t *testing.T) {
	id, err := threadIDFromMeta(map[string]any{"threadId": "01a0-abc", "itemId": "x"})
	if err != nil || id != "01a0-abc" {
		t.Fatalf("threadIDFromMeta = %q, %v", id, err)
	}
	if _, err := threadIDFromMeta(nil); !IsNoThreadID(err) {
		t.Errorf("nil meta should report no thread id, got %v", err)
	}
	if _, err := threadIDFromMeta(map[string]any{"itemId": "x"}); !IsNoThreadID(err) {
		t.Errorf("meta without a thread id should say so, got %v", err)
	}
	// A wrong type is a real error, not "absent": something is malformed.
	if _, err := threadIDFromMeta(map[string]any{"threadId": 42}); err == nil || IsNoThreadID(err) {
		t.Errorf("a non-string thread id should be an error, got %v", err)
	}
	if _, err := threadIDFromMeta(map[string]any{"threadId": "  "}); err == nil {
		t.Error("a blank thread id should be refused")
	}
}

// Latch once. A second, different parent means two sessions are reaching this
// process — the condition parent-only exists to prevent — so the backend must
// fail closed rather than keep serving whichever it saw first.
func TestAdoptLatchesOnceAndFailsClosedOnMismatch(t *testing.T) {
	c := &codexBackend{}
	if err := c.Adopt(map[string]any{"threadId": "thread-a"}); err != nil {
		t.Fatalf("first adopt: %v", err)
	}
	// Repeats are free: the caller is expected to call on every request.
	for i := 0; i < 3; i++ {
		if err := c.Adopt(map[string]any{"threadId": "thread-a"}); err != nil {
			t.Fatalf("repeat adopt: %v", err)
		}
	}
	if c.thread != "thread-a" {
		t.Fatalf("thread = %q, want it latched", c.thread)
	}

	err := c.Adopt(map[string]any{"threadId": "thread-b"})
	if err == nil {
		t.Fatal("a second parent thread must be an error, never a retarget")
	}
	if !strings.Contains(err.Error(), "thread-b") || !strings.Contains(err.Error(), "thread-a") {
		t.Errorf("the error should name both threads: %v", err)
	}
	if c.thread == "thread-b" {
		t.Fatal("the backend retargeted, which is exactly what must not happen")
	}
	ok, reason := c.Available()
	if ok {
		t.Error("after a mismatch the backend must be unavailable for the rest of its life")
	}
	if !strings.Contains(reason, "more than one session") {
		t.Errorf("reason = %q, want it to explain the mismatch", reason)
	}
	// Still disabled even if the original thread identifies itself again.
	if err := c.Adopt(map[string]any{"threadId": "thread-a"}); err == nil {
		t.Error("a disabled backend must stay disabled")
	}
	if _, err := c.Deliver(context.Background(), Delivery{Cursor: "c", Body: "x"}); err == nil {
		t.Error("a disabled backend must refuse to deliver")
	}
}

// Before any tool call there is no target, and the reason has to be a sentence
// a model can be shown rather than an error code.
func TestCodexUnavailableBeforeAdopt(t *testing.T) {
	c := &codexBackend{}
	ok, reason := c.Available()
	if ok {
		t.Skip("a Codex daemon with a latched thread is not what this test is about")
	}
	if reason == "" || !strings.Contains(reason, "not") {
		t.Errorf("reason = %q, want a sentence explaining the negative", reason)
	}
	if _, err := c.Deliver(context.Background(), Delivery{Cursor: "c", Body: "x"}); err == nil {
		t.Error("delivering with no target must fail")
	}
}

// Nothing in this package takes an address, and nothing reads the session
// registry or a peer key file — those are the address book. This test pins
// the API surface, because the guarantee is "cannot express it", not "does
// not currently do it".
func TestNoAPITakesAnAddress(t *testing.T) {
	var d Deliverer = &claudeBackend{socket: "/nonexistent.sock"}
	// Adopt is the only input that names anything, and on Claude it cannot
	// change the target at all.
	if err := d.Adopt(map[string]any{"threadId": "somebody-else"}); err != nil {
		t.Errorf("Adopt on the Claude backend should be a harmless no-op: %v", err)
	}
	c := d.(*claudeBackend)
	if c.socket != "/nonexistent.sock" {
		t.Error("Adopt changed the Claude target; it must come from the environment only")
	}
}

func TestClaudeMaxIntactBytesLeavesRoomForEscaping(t *testing.T) {
	c := &claudeBackend{socket: "/tmp/x.sock"}
	max, err := c.MaxIntactBytes()
	if err != nil {
		t.Fatal(err)
	}
	// Halved, because JSON escaping can double the payload on the wire and
	// an oversize line costs the whole connection.
	if max >= udsmsg.MaxLineBytes/2 {
		t.Errorf("MaxIntactBytes = %d; it must leave room for envelope and escaping", max)
	}
	if max < 64<<10 {
		t.Errorf("MaxIntactBytes = %d; that is too conservative to be useful", max)
	}
}

func TestObservationStrings(t *testing.T) {
	for o, want := range map[Observation]string{
		ObservedNothing:  "nothing",
		ObservedTurnRan:  "turn-ran",
		ObservedAccepted: "accepted",
		ObservedStored:   "stored",
		ObservedConsumed: "consumed",
	} {
		if got := o.String(); got != want {
			t.Errorf("Observation(%d) = %q, want %q", int(o), got, want)
		}
	}
}

// A Codex shell-tool child is told its thread at exec, the same way a Claude
// child is told its socket. Such a process is not an MCP server and will never
// see tool-call metadata, so it must be served without Adopt.
func TestCodexShellChildIsServedFromTheEnvironment(t *testing.T) {
	t.Setenv(EnvClaudeSocket, "")
	t.Setenv(EnvCodexThread, "01a0-from-env")

	d, ok := Open().(*codexBackend)
	if !ok {
		t.Fatal("with no Claude socket the Codex backend should be selected")
	}
	if d.thread != "01a0-from-env" {
		t.Errorf("thread = %q, want it latched from %s", d.thread, EnvCodexThread)
	}
	// Still latch-once: the environment does not get a special exemption
	// from the rule that a second thread disables delivery.
	if err := d.Adopt(map[string]any{"threadId": "somebody-else"}); err == nil {
		t.Error("a thread from tool metadata must not override the one from the environment")
	}
	if ok, _ := d.Available(); ok {
		t.Error("after a mismatch the backend must be unavailable")
	}
}

// A process no harness spawned has nothing inherited and nothing to adopt, and
// must say so rather than looking for a session to talk to.
func TestProcessWithNoHarnessHasNoTarget(t *testing.T) {
	t.Setenv(EnvClaudeSocket, "")
	t.Setenv(EnvCodexThread, "")
	t.Setenv("CODEX_HOME", t.TempDir())

	ok, reason := Open().Available()
	if ok {
		t.Fatal("a process with no harness must not find one")
	}
	if !strings.Contains(reason, "harness") {
		t.Errorf("reason = %q, want it to say no harness launched this process", reason)
	}
}

// The two size figures answer different questions and must not be conflated:
// one is what this code enforces, the other is what an experiment showed.
func TestTheTwoSizeFiguresAnswerDifferentQuestions(t *testing.T) {
	c := &claudeBackend{socket: "/tmp/x.sock"}
	max, err := c.MaxIntactBytes()
	if err != nil {
		t.Fatal(err)
	}
	// The measured figure exceeding the enforced one is expected, not a
	// contradiction: the enforced one is halved so it holds for content that
	// is all quotes and newlines, while the measurement used ordinary text
	// that barely needed escaping. What must never happen is the enforced
	// figure exceeding the transport cap it is derived from.
	if max*2 >= udsmsg.MaxLineBytes {
		t.Errorf("the refusal threshold (%d) must leave room for worst-case escaping under the %d cap",
			max, udsmsg.MaxLineBytes)
	}
	if DemonstratedIntactBytes != 1_000_000 {
		t.Errorf("DemonstratedIntactBytes = %d; change it only with a new experiment, and update the recorded method",
			DemonstratedIntactBytes)
	}
}

// The floor must hold for content nobody inspected. JSON inflates "<", ">",
// "&" and control characters sixfold — not twofold, as quotes and newlines
// suggest — so a body of angle brackets at exactly MaxIntactBytes has to
// still fit the wire, or the number is a promise the transport cannot keep.
func TestWorstCaseContentAtTheFloorStillFits(t *testing.T) {
	p := startParent(t)
	d := newClaude(p.srv.Path(), "", "test-client", "", udsmsg.ModePrompting)
	max, err := d.MaxIntactBytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, worst := range []string{"<", ">", "&", "\x01", `"`, "\n"} {
		body := strings.Repeat(worst, max)
		ok, wire, err := d.Fits(Delivery{Body: body})
		if err != nil {
			t.Fatalf("Fits(%q x %d): %v", worst, max, err)
		}
		if !ok {
			t.Errorf("a %d-byte body of %q encodes to %d bytes, over the cap — "+
				"MaxIntactBytes promises more than the transport accepts", max, worst, wire)
		}
	}
}

// Fits is the escape hatch from the worst case: prose reaches far higher
// than the floor, and a caller holding the body should not be held to a
// limit derived from content it does not have.
func TestFitsAllowsFarMoreProseThanTheFloor(t *testing.T) {
	p := startParent(t)
	d := newClaude(p.srv.Path(), "", "test-client", "", udsmsg.ModePrompting)
	max, _ := d.MaxIntactBytes()

	ok, wire, err := d.Fits(Delivery{Cursor: "c", Body: strings.Repeat("ordinary prose ", max/3)})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("prose of %d bytes did not fit (%d on the wire); the floor should not bind text that does not escape", max*5, wire)
	}
}

// A guard that clears one backend's variables leaves the other backend live.
// This is the whole reason the helper belongs in this package: the list of
// what to clear is the list of what is read.
func TestClearEnvForTestingCoversEveryBackend(t *testing.T) {
	t.Setenv(EnvClaudeSocket, "/run/user/0/cc-socks/4242.sock")
	t.Setenv(EnvClaudeToken, "cafebabe")
	t.Setenv(EnvCodexThread, "01a0-live-thread")

	restore := ClearEnvForTesting()
	for _, k := range harnessEnv {
		if v, ok := os.LookupEnv(k); ok {
			t.Errorf("%s survived as %q; a delivery path would still find a harness", k, v)
		}
	}
	// With nothing inherited, the Codex backend must not have latched a
	// target from the environment either.
	if c, ok := Open().(*codexBackend); ok && c.thread != "" {
		t.Errorf("Codex target %q latched despite a cleared environment", c.thread)
	}

	restore()
	if os.Getenv(EnvClaudeSocket) != "/run/user/0/cc-socks/4242.sock" || os.Getenv(EnvCodexThread) != "01a0-live-thread" {
		t.Error("restore did not put the environment back")
	}
}

// A peer the kernel will not identify carries no identity, and the zero
// value of a pid is 0 — which compares equal to nothing useful and unequal
// to everything real. Identified is what tells the two apart.
func TestAnUnidentifiedPeerIsNotAPidOfZero(t *testing.T) {
	var absent udsmsg.Peer
	if absent.Identified {
		t.Error("the zero value must not claim to be identified")
	}
	real := udsmsg.Peer{PID: 4242, Identified: true}
	if !real.Identified {
		t.Error("a peer the kernel answered for should say so")
	}
}
