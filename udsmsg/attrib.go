package udsmsg

import (
	"regexp"
	"strings"
	"unicode"
)

// A session does not assert its identity in protocol fields — the receiver
// discards those. It writes the attribution into the prompt itself, as an
// element the receiving harness parses out of message.content and renders as
// an attributed peer message. Sending bare text instead injects an anonymous
// prompt: the peer sees no sender name and no reply address it trusts.
//
// What the receiver requires of the element was measured against Claude Code
// 2.1.272 on 2026-09-17, by sending variants to a live session and reading
// which arrived as attributed messages and which arrived as raw markup:
//
//   - the newline after the open tag and before the close tag are REQUIRED
//   - a "<" or ">" inside an attribute value is REQUIRED to be absent
//   - a literal newline inside an attribute value is REQUIRED to be absent
//
// Everything else that looks load-bearing is not: attribute order, single
// spaces between attributes, a closing tag appearing inside the body, the
// length of a name, and invisible characters in one were all accepted. All
// three attributes are optional, and with no from-name the receiver displays
// the sender's pid instead.
//
// A double quote in a name is the one case that neither breaks nor survives:
// it closes the attribute early, so the name is silently truncated there.
// ScrubName removes it to protect the name rather than the envelope.

// MsgVersion is the envelope version a session stamps on a user frame. The
// receiver never reads it: it is emitted for fidelity, not required.
const MsgVersion = 1

// Queue priorities. The receiver passes these three through and normalises
// everything else — absent, unknown or malformed — to PriorityNext. A bad
// value never drops a frame.
const PriorityNext = "next"

// Element name and the attributes. This order is the one a captured session
// frame used; it is not required, and was measured not to be.
const (
	csElement = "cross-session-message"
	attrFrom  = "from"
	attrName  = "from-name"
	attrMode  = "from-mode"
)

var (
	// fromRe is the reply address guard applied to the from attribute.
	fromRe = regexp.MustCompile(`^[A-Za-z0-9%:_/.\\-]{1,300}$`)
)

// CrossSession is the attribution a user frame carries in its own content.
type CrossSession struct {
	// From is our reply address, "uds:<socket path>". Omitted when we have no
	// inbox, leaving the peer a name but no way back.
	From string
	// Name is how the peer sees us, e.g. "chat-relay (build)".
	Name string
	// Mode is our permission posture.
	Mode Mode
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
	attr(attrName, ScrubName(cs.Name))
	if cs.Mode == ModePrompting {
		attr(attrMode, string(cs.Mode))
	}
	b.WriteString(">\n")
	b.WriteString(text)
	b.WriteString("\n</")
	b.WriteString(csElement)
	b.WriteString(">")
	return b.String()
}

// ScrubName removes from a sender name the characters measured to matter, and
// nothing else. An angle bracket or a literal newline inside an attribute
// costs the whole element, which is why they go; a double quote costs the rest
// of the name, which is why it goes too. They are removed rather than escaped
// because no escaping was ever observed in a session's own frame.
//
// Everything a name may otherwise contain is left alone: a 5000-rune name and
// an invisible character were both accepted whole, so nothing here shortens or
// sanitises beyond what was shown to be necessary.
func ScrubName(name string) string {
	name = strings.Map(func(r rune) rune {
		switch r {
		case '"', '<', '>':
			return -1
		}
		if unicode.Is(unicode.Cc, r) {
			return -1
		}
		return r
	}, name)
	return strings.TrimSpace(name)
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
//
// The element must span the WHOLE content: the pattern is anchored, so an
// envelope sitting inside a larger body does not match and its attribution is
// never reported alongside text that is not part of it. That anchoring is the
// property worth having here.
//
// Attributes this package does not model are ignored rather than fatal, and
// nothing re-renders the parsed result to check it. Reading our own mail does
// not require reproducing the receiving harness's verdict on what counts as
// attributed — and a parser that answered that question would break on any
// attribute the protocol grew, by construction and in silence.
//
// What this does NOT do is authenticate anyone. Every attribute here is a
// claim the sender composed, from-name included. Identity comes from the
// kernel's credentials on the connection, which no sender can choose.
func Unwrap(content string) (cs CrossSession, body string, ok bool) {
	m := wrapperRe.FindStringSubmatch(content)
	if m == nil {
		return CrossSession{}, content, false
	}
	for _, a := range attrRe.FindAllStringSubmatch(m[1], -1) {
		switch a[1] {
		case attrFrom:
			cs.From = a[2]
		case attrName:
			cs.Name = a[2]
		case attrMode:
			cs.Mode = Mode(a[2])
		}
	}
	return cs, m[2], true
}
