package udsmsg

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Attribution is an element inside message.content: an accepted one is shown
// as an attributed message, bare text arrives anonymous. What it requires, and
// what it does not, is in docs/claude-uds-messaging.adoc.

// msgVersion is what sessions were seen to stamp on a user frame.
const msgVersion = 1

// priorityNext is the queue priority sessions were observed to send.
const priorityNext = "next"

// Element name and attributes, in the order a captured frame used — measured
// not to be required.
const (
	csElement = "cross-session-message"
	attrFrom  = "from"
	attrName  = "from-name"
	attrMode  = "from-mode"
)

var (
	// fromRe guards the from attribute: the characters an address is made of,
	// bounded by maxSocketPath plus the scheme and its colon.
	fromRe = regexp.MustCompile(fmt.Sprintf(`^[A-Za-z0-9:_/.-]{1,%d}$`, len(schemeUDS)+1+maxSocketPath))
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

// Wrap renders text as an attributed cross-session message. An empty or
// unusable attribute is omitted rather than corrected: correcting it would
// assert something the caller did not say.
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
	attr(attrName, scrubName(cs.Name))
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

// scrubName removes only what was measured to matter: angle brackets and
// newlines cost the whole element, a double quote costs the rest of the name.
// Removed rather than escaped — no session frame was seen to escape anything.
func scrubName(name string) string {
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

// The element resembles XML and is not, so these match a byte template rather
// than parse a document: an XML parser accepts quoting a session never sends,
// and would invent attributions nobody wrote.

// wrapperRe matches a whole content string that is one attributed message.
var wrapperRe = regexp.MustCompile(`(?s)\A<` + csElement + `\b([^>]*)>\n(.*)\n</` + csElement + `>\z`)

// attrRe pulls one attribute out of the open tag.
var attrRe = regexp.MustCompile(`([a-z-]+)="([^"]*)"`)

// Unwrap parses an attributed message into the attribution and the body. The
// element must span the WHOLE content — the pattern is anchored — so one
// quoted inside a larger body is not attribution for it. Unknown attributes
// are ignored rather than fatal.
//
// This authenticates nobody: every attribute is the sender's claim, and
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
