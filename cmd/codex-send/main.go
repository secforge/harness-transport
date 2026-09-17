// Command codex-send queues a message into a running Codex session through
// the local app-server daemon, the way claude-send does for a Claude Code
// session.
//
// The two protocols are opposites. Claude Code is a mesh: a socket per
// session, peers addressing each other by socket path, identity from
// SO_PEERCRED and a token. Codex is a hub: one daemon owns every thread and a
// client names a thread by id. So there is no inbox to bind here and no reply
// address to publish — and no reply, either. A queued message joins a
// session's queue; what the session does with it appears in that session's
// own UI.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/secforge/harness-transport/codexmsg"
)

const (
	exitOK       = 0
	exitError    = 1
	exitNoTarget = 6
)

func main() { os.Exit(run()) }

func run() int {
	var (
		to      = flag.String("to", "", "thread id to queue into")
		socket  = flag.String("socket", "", "control socket path (default: $CODEX_HOME/app-server-control/app-server-control.sock)")
		name    = flag.String("name", "codex-send", "client name recorded in thread metadata")
		timeout = flag.Duration("timeout", 30*time.Second, "give up after this long")
		jsonOut = flag.Bool("json", false, "print results as JSON")
	)
	flag.Usage = usage
	flag.Parse()

	text := strings.Join(flag.Args(), " ")
	if *to == "" || text == "" {
		usage()
		return exitError
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	c, err := codexmsg.Dial(ctx, codexmsg.Options{SocketPath: *socket})
	if err != nil {
		fmt.Fprintf(os.Stderr, "codex-send: %v\n", err)
		return exitNoTarget
	}
	defer c.Close()

	// The app server expects the handshake before anything else, and the
	// name given here is what shows up in thread metadata.
	if _, err := c.Initialize(ctx, codexmsg.InitializeParams{
		ClientInfo: codexmsg.ClientInfo{Name: *name, Version: "0.1.0"},
		// thread/queue/add is refused without it.
		Capabilities: &codexmsg.Capabilities{ExperimentalAPI: true},
	}); err != nil {
		fmt.Fprintf(os.Stderr, "codex-send: initialize: %v\n", err)
		return exitError
	}

	res, err := c.QueueMessage(ctx, *to, text, codexmsg.NewUUIDv7())
	if err != nil {
		fmt.Fprintf(os.Stderr, "codex-send: %v\n", err)
		return exitError
	}
	if *jsonOut {
		b, _ := json.Marshal(res)
		fmt.Println(string(b))
	} else {
		fmt.Printf("Queued message %s for thread %s.\n", res.QueuedSubmission.ID, *to)
	}
	return exitOK
}

func usage() {
	fmt.Fprint(os.Stderr, `codex-send — queue a message into a Codex session on this machine

  codex-send --list
  codex-send --to <thread-uuid|name> [flags] <message text>

`)
	flag.PrintDefaults()
}
