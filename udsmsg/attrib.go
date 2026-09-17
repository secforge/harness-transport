package udsmsg

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Attribution is an element inside message.content; an accepted one is shown
// as an attributed message with the markup gone, and bare text arrives
// anonymous — no sender name, no address to answer.
//
// What the element requires was measured against Claude Code 2.1.272 on
// 2026-09-17, by sending variants to a live session and reading which arrived
// attributed and which arrived as raw markup. Three things are required:
//
//   - the newline after the open tag and before the close tag
//   - no "<" or ">" inside an attribute value
//   - no literal newline inside an attribute value
//
// Nothing else is: attribute order, single spaces, a closing tag in the body,
// name length and invisible characters were all accepted, and all three
// attributes are optional (with no from-name the sender's pid is shown).
//
// A double quote neither breaks nor survives — it closes the value early and
// the name is silently truncated. ScrubName removes it to protect the name.

// MsgVersion is what sessions were seen to stamp on a user frame. What a
// recipient does with it is not observable.
const MsgVersion = 1

// PriorityNext is the queue priority sessions were observed to send.
const PriorityNext = "next"

// Element name and attributes, in the order a captured frame used — measured
// not to be required.
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

// ScrubName removes only what was measured to matter: an angle bracket or
// newline costs the whole element, a double quote costs the rest of the name.
// Removed rather than escaped, since no session frame was seen to escape.
// Everything else is left alone — a 5000-rune name and an invisible character
// were both accepted whole.
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

// Unwrap parses an attributed message into the attribution and the body.
//
// The element must span the WHOLE content — the pattern is anchored — so an
// envelope quoted inside a larger body is not reported as attribution for it.
//
// Unknown attributes are ignored rather than fatal, and nothing re-renders the
// result to check it: reading our own mail does not require reproducing a
// harness's verdict, and a parser that tried would break on any attribute the
// protocol grew.
//
// This authenticates nobody. Every attribute is a claim the sender composed;
// identity comes from the kernel's credentials on the connection.
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
