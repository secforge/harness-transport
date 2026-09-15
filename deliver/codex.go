package deliver

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"unicode/utf8"

	"github.com/secforge/harness-transport/codexmsg"
)

// codexBackend delivers into the Codex harness thread that launched us.
//
// Codex does not put a thread id in an MCP server's environment — it injects
// CODEX_THREAD_ID into shell-tool children only — so the target cannot be read
// at startup. It arrives instead on every MCP request as _meta.threadId, which
// is the harness naming itself over the pipe it spawned us on. Adopt latches
// that, once.
type codexBackend struct {
	mu sync.Mutex
	// thread is the latched target. Empty until the first request carrying
	// meta arrives.
	thread string
	// disabled is set when two different thread ids have been seen. Two
	// sessions reaching one MCP process is the condition harness-only exists
	// to prevent, so the backend fails closed for the rest of its life
	// rather than continuing to serve whichever target it latched first.
	disabled bool
	client   *codexmsg.Client
	name     string
}

func newCodex(name string) *codexBackend {
	if name == "" {
		name = defaultSenderName()
	}
	return &codexBackend{name: name}
}

// codexMaxChars is the daemon's hard limit, which it enforces with a
// structured error rather than by truncating. It counts CHARACTERS, not
// bytes — "Input exceeds the maximum length of 1048576 characters" — so a
// byte count compared against it is a different quantity that happens to be
// conservative for UTF-8 rather than a correct comparison.
const codexMaxChars = 1 << 20

// No conversion is needed between the daemon's character limit and the byte
// figure MaxIntactBytes hands out, and the intuition that there is one is
// backwards. In UTF-8 every character costs at least one byte, so for any
// string characters <= bytes: a body within a byte budget of N can never
// exceed N characters. The multiplication by four applies in the opposite
// direction — bounding bytes from a character budget — which is not the
// direction this method runs. It holds under UTF-16 counting too, where a
// four-byte character is two units and ASCII is the worst case at one unit
// per byte.

// codexOverhead is reserved for the cursor trailer.
const codexOverhead = 4 << 10

func (c *codexBackend) MaxIntactBytes() (int, error) {
	if ok, reason := c.Available(); !ok {
		return 0, fmt.Errorf("%s", reason)
	}
	return codexMaxChars - codexOverhead, nil
}

// Fits reports whether the daemon will take this delivery, counting what the
// daemon counts: characters. Escaping does not enter into it, and neither
// does byte length — an accented or CJK body is refused far too early by a
// byte comparison, which is safe and wrong.
//
// The returned size is in bytes, since that is what a caller measuring a
// payload has; the decision is made on runes.
func (c *codexBackend) Fits(d Delivery) (bool, int, error) {
	text := compose(d)
	return utf8.RuneCountInString(text) <= codexMaxChars, len(text), nil
}

func (c *codexBackend) Available() (bool, string) {
	c.mu.Lock()
	thread, disabled := c.thread, c.disabled
	c.mu.Unlock()

	if disabled {
		return false, "two different harness threads have identified themselves to this process, which means more than one session is reaching it; " +
			"delivery is disabled for the lifetime of this process rather than risk delivering into a session that did not launch it"
	}
	if _, err := codexmsg.DefaultSocket(); err != nil {
		return false, "this process was not launched by a reachable Claude Code or Codex harness: " + err.Error()
	}
	if thread == "" {
		return false, "the Codex harness has not identified its thread yet: the thread id is carried on MCP tool-call metadata, " +
			"and no call carrying it has arrived, so there is nothing to deliver into"
	}
	return true, "the Codex harness thread is reachable"
}

// Adopt latches the target from an inbound request's metadata.
//
// It accepts only what the harness sent. It latches once; a second, different
// thread id does not retarget but disables the backend permanently, so the
// worst a confused caller can do is fail rather than redirect.
func (c *codexBackend) Adopt(meta map[string]any) error {
	id, err := threadIDFromMeta(meta)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.disabled:
		return fmt.Errorf("delivery is disabled: more than one harness thread has identified itself to this process")
	case c.thread == "":
		c.thread = id
		return nil
	case c.thread == id:
		return nil
	default:
		c.disabled = true
		was := c.thread
		c.thread = ""
		return fmt.Errorf("a second harness thread %s identified itself after %s: more than one session is reaching this process, "+
			"so delivery is now disabled for its lifetime", id, was)
	}
}

func (c *codexBackend) Close() error {
	c.mu.Lock()
	client := c.client
	c.client = nil
	c.mu.Unlock()
	if client != nil {
		return client.Close()
	}
	return nil
}

// connect returns a live client, dialling and initializing on first use.
// thread/queue/add is refused without the experimental capability.
func (c *codexBackend) connect(ctx context.Context) (*codexmsg.Client, error) {
	c.mu.Lock()
	if c.client != nil {
		client := c.client
		c.mu.Unlock()
		return client, nil
	}
	c.mu.Unlock()

	client, err := codexmsg.Dial(ctx, codexmsg.Options{})
	if err != nil {
		return nil, err
	}
	if _, err := client.Initialize(ctx, codexmsg.InitializeParams{
		ClientInfo:   codexmsg.ClientInfo{Name: c.senderName(), Version: "0.1.0"},
		Capabilities: &codexmsg.Capabilities{ExperimentalAPI: true},
	}); err != nil {
		client.Close()
		return nil, fmt.Errorf("initialize: %w", err)
	}

	c.mu.Lock()
	if c.client != nil { // another caller won the race
		other := c.client
		c.mu.Unlock()
		client.Close()
		return other, nil
	}
	c.client = client
	c.mu.Unlock()
	return client, nil
}

// senderName is the client name reported to the daemon, which records it as
// the thread's originator.
func (c *codexBackend) senderName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.name == "" {
		return defaultSenderName()
	}
	return c.name
}

func (c *codexBackend) Deliver(ctx context.Context, d Delivery) (Receipt, error) {
	ok, reason := c.Available()
	if !ok {
		return Receipt{}, fmt.Errorf("cannot deliver: %s", reason)
	}
	c.mu.Lock()
	thread := c.thread
	c.mu.Unlock()

	text := compose(d)
	if ok, _, _ := c.Fits(d); !ok {
		return Receipt{SentBytes: len(text)}, fmt.Errorf(
			"message is %d characters, over the %d the daemon accepts; "+
				"deliver a shorter body and leave the rest to be fetched from the cursor",
			utf8.RuneCountInString(text), codexMaxChars)
	}

	client, err := c.connect(ctx)
	if err != nil {
		return Receipt{SentBytes: len(text)}, fmt.Errorf("the Codex daemon did not accept a connection: %w", err)
	}

	res, err := client.QueueMessage(ctx, thread, text, "")
	if err != nil {
		// A failed connection may be stale; drop it so the next delivery
		// redials rather than inheriting a dead socket.
		c.Close()
		return Receipt{SentBytes: len(text)}, fmt.Errorf("the daemon did not queue the message: %w", err)
	}

	// The daemon echoes what it stored. Comparing it is the difference
	// between "it said yes" and "it holds exactly these bytes".
	echo := ""
	if len(res.QueuedSubmission.Input) > 0 {
		echo = res.QueuedSubmission.Input[0].Text
	}
	verified := echo != "" && sha256.Sum256([]byte(echo)) == sha256.Sum256([]byte(text))

	r := Receipt{
		SentBytes: len(text),
		Ref:       thread + "/" + res.QueuedSubmission.ID,
	}
	if verified {
		r.Observation = ObservedStored
		r.EchoVerified = true
		r.Detail = "Queued on the Codex harness thread, which returned a receipt echoing the message; the echo matched byte for byte, " +
			"so the thread holds exactly what was sent. The model has not necessarily read it yet."
		return r, nil
	}
	r.Observation = ObservedAccepted
	r.Detail = fmt.Sprintf("Queued on the Codex harness thread, which acknowledged it, but the echoed content did not match what was sent "+
		"(%d bytes sent, %d echoed), so integrity is unconfirmed — re-read from the cursor before relying on the body.",
		len(text), len(echo))
	return r, nil
}
