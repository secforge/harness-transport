package udsmsg

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A session does not assert its identity in protocol fields — the receiver
// discards those. It writes the attribution into the prompt itself, as an
// element the receiving harness parses out of message.content and renders as
// an attributed peer message. Sending bare text instead injects an anonymous
// prompt: the peer sees no sender name and no reply address it trusts.
//
// The receiver's parser re-renders what it parsed and compares it byte for
// byte against the input; anything that does not round-trip is treated as
// plain text. So attribute order, the single spaces, the newline after the
// open tag and before the close tag, and the name scrubbing below are all
// load-bearing.

// MsgVersion is the envelope version a session stamps on a user frame. The
// receiver never reads it: it is emitted for fidelity, not required.
const MsgVersion = 1

// Queue priorities. The receiver passes these three through and normalises
// everything else — absent, unknown or malformed — to PriorityNext. A bad
// value never drops a frame.
const (
	// PriorityNow is accepted and passed through.
	PriorityNow = "now"
	// PriorityNext is the normal path for a peer's prompt.
	PriorityNext = "next"
	// PriorityLater is what a session uses for batched internal notices.
	PriorityLater = "later"
)

// Element name and the attributes, in the order they must be rendered.
const (
	csElement  = "cross-session-message"
	attrFrom   = "from"
	attrSess   = "from-session"
	attrHops   = "hop-chain"
	attrName   = "from-name"
	attrMode   = "from-mode"
	maxNameLen = 64
	maxHops    = 32
)

var (
	// fromRe is the reply address guard applied to the from attribute.
	fromRe = regexp.MustCompile(`^[A-Za-z0-9%:_/.\\-]{1,300}$`)
	// sessionRe guards the from-session attribute.
	sessionRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
	// hopRe guards the joined hop chain.
	hopRe = regexp.MustCompile(`^[0-9a-f]{24}(,[0-9a-f]{24})*$`)
	// nestedClose rewrites a closing tag inside the body, which would
	// otherwise terminate the element early.
	nestedClose = regexp.MustCompile(`</` + csElement + `\s*>`)
)

// CrossSession is the attribution a user frame carries in its own content.
type CrossSession struct {
	// From is our reply address, "uds:<socket path>". Omitted when we have no
	// inbox, leaving the peer a name but no way back.
	From string
	// Session optionally identifies our session.
	Session string
	// HopChain is the relay path. Leave it empty unless relaying: the
	// receiver drops a frame whose chain already contains it, as a loop.
	HopChain []string
	// Name is how the peer sees us, e.g. "chat-relay (build)".
	Name string
	// Mode is our permission posture.
	Mode Mode
}

// hopKey is a secret generated once per process, exactly as a session does.
// It makes a hop token a function of the address it names, so the token is
// stable for the life of this process, changes on restart, and cannot be
// computed by anyone else.
var hopKey = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("udsmsg: crypto/rand failed: " + err.Error())
	}
	return b
}()

// HopToken returns this process's hop-chain token for an address: the first 24
// hex characters of HMAC-SHA256(hopKey, addr).
//
// Only a relay needs one. A receiver drops a frame whose chain already
// contains its own token, which is what terminates a relay cycle.
func HopToken(addr string) string {
	m := hmac.New(sha256.New, hopKey)
	m.Write([]byte(addr))
	return hex.EncodeToString(m.Sum(nil))[:24]
}

// Wrap renders text as an attributed cross-session message. An attribute that
// is empty, or that fails its guard, is omitted rather than corrected: an
// attribute the receiver would reject costs the whole wrapper, while a missing
// one costs only that field.
func (cs CrossSession) Wrap(text string) string {
	var b strings.Builder
	b.WriteString("<")
	b.WriteString(csElement)
	attr := func(k, v string) {
		if v == "" {
			return
		}
		b.WriteString(" ")
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(v)
		b.WriteString(`"`)
	}
	if fromRe.MatchString(cs.From) {
		attr(attrFrom, cs.From)
	}
	if sessionRe.MatchString(cs.Session) {
		attr(attrSess, cs.Session)
	}
	if hops := joinHops(cs.HopChain); hops != "" {
		attr(attrHops, hops)
	}
	attr(attrName, ScrubName(cs.Name))
	switch cs.Mode {
	case ModePrompting, ModeBypass:
		attr(attrMode, string(cs.Mode))
	}
	b.WriteString(">\n")
	b.WriteString(EscapeBody(text))
	b.WriteString("\n</")
	b.WriteString(csElement)
	b.WriteString(">")
	return b.String()
}

// joinHops renders a hop chain, capped at the length the receiver accepts.
// A chain that does not match the guard is dropped whole.
func joinHops(hops []string) string {
	if len(hops) == 0 {
		return ""
	}
	if len(hops) > maxHops {
		hops = hops[:maxHops]
	}
	s := strings.Join(hops, ",")
	if !hopRe.MatchString(s) {
		return ""
	}
	return s
}

// ScrubName normalises a sender name the way the receiver does: the three
// characters that would break out of the attribute are removed, not escaped —
// escaping them would fail the receiver's byte-for-byte round-trip check.
// Invisible and control characters are stripped, the result trimmed, and a
// long name truncated.
func ScrubName(name string) string {
	name = strings.Map(func(r rune) rune {
		switch r {
		case '"', '<', '>':
			return -1
		}
		if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Cc, r) ||
			unicode.Is(unicode.Cs, r) || unicode.Is(unicode.Zl, r) ||
			unicode.Is(unicode.Zp, r) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > maxNameLen {
		name = string([]rune(name)[:maxNameLen]) + "…"
	}
	return name
}

// EscapeBody neutralises a closing tag inside the body, which would otherwise
// end the element early and leave the remainder as loose text.
func EscapeBody(text string) string {
	return nestedClose.ReplaceAllString(text, `<\`)
}

// The two expressions below deliberately mirror the receiver's own, which are
// regexps too. This element is not XML: it is a fixed byte template that
// resembles it, and the receiver accepts exactly one rendering of it. An XML
// parser would be the wrong tool — it accepts single quotes, entity
// references, comments, reordered attributes and extra whitespace, none of
// which the peer accepts, so we would report an attribution the peer never
// rendered. Neither expression is load-bearing for correctness: they only
// propose a candidate, and the round-trip comparison in Unwrap is what
// validates it.

// wrapperRe matches a whole content string that is one attributed message.
var wrapperRe = regexp.MustCompile(`(?s)\A<` + csElement + `\b([^>]*)>\n(.*)\n</` + csElement + `>\z`)

// attrRe pulls one attribute out of the open tag.
var attrRe = regexp.MustCompile(`([a-z-]+)="([^"]*)"`)

// Unwrap parses an attributed message, returning the attribution and the body.
// It applies the receiver's own test — re-render what was parsed and require
// it to equal the input — so a string that merely looks like a wrapper is
// reported as plain text (ok == false), exactly as the peer would treat it.
// That equality, not the pattern match, is what makes a forged or malformed
// envelope unreportable.
func Unwrap(content string) (cs CrossSession, body string, ok bool) {
	m := wrapperRe.FindStringSubmatch(content)
	if m == nil {
		return CrossSession{}, content, false
	}
	for _, a := range attrRe.FindAllStringSubmatch(m[1], -1) {
		switch a[1] {
		case attrFrom:
			cs.From = a[2]
		case attrSess:
			cs.Session = a[2]
		case attrHops:
			cs.HopChain = strings.Split(a[2], ",")
		case attrName:
			cs.Name = a[2]
		case attrMode:
			cs.Mode = Mode(a[2])
		}
	}
	body = m[2]
	if cs.Wrap(body) != content {
		return CrossSession{}, content, false
	}
	return cs, body, true
}
