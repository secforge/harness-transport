package udsmsg

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// A session writes its attribution into the prompt itself, as an element
// inside message.content, and a recipient shows an accepted one as an
// attributed message with the markup gone. Sending bare text instead delivers
// an anonymous prompt — no sender name, no address to answer.
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

// MsgVersion is the envelope version a session stamps on a user frame. What a
// recipient does with it is not observable from outside, so we send what
// sessions were seen to send.
const MsgVersion = 1

// PriorityNext is the queue priority sessions were observed to send. Whether
// others are accepted, and what they would do, is not observable from here.
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
	// fromRe is the guard applied to the from attribute: the characters an
	// address on this transport is made of, and no more.
	//
	// The bound is the operating system's rather than a guess: see
	// MaxSocketPath, which the scheme and its colon add four to.
	fromRe = regexp.MustCompile(fmt.Sprintf(`^[A-Za-z0-9:_/.-]{1,%d}$`, len(SchemeUDS)+1+MaxSocketPath))
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
// is empty, or that fails its guard, is omitted rather than corrected — a
// missing attribute costs only itself, while a corrected one would assert
// something the caller did not say.
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

// This element resembles XML and is not XML, so the two expressions below
// match a byte template rather than parse a document. An XML parser would
// accept single quotes, entity references, comments and CDATA, none of which
// has ever been seen in a session's frame — reading them would invent an
// attribution nobody wrote.

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
