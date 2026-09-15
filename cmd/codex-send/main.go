// Command codex-send queues a message into a running Codex session through
// the local app-server daemon, the way claude-send does for a Claude Code
// session.
//
// The two protocols are opposites. Claude Code is a mesh: a socket per
// session, peers addressing each other by socket path, identity from
// SO_PEERCRED and a token. Codex is a hub: one daemon owns every thread, and
// a client names a thread by UUID or by name. So there is no inbox to bind
// here and no reply address to publish — and no reply, either. A queued
// message joins a session's queue; what the session does with it appears in
// that session's own UI.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
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
		list    = flag.Bool("list", false, "list threads on the daemon and exit")
		all     = flag.Bool("all", false, "with --list, include archived threads")
		to      = flag.String("to", "", "thread UUID or exact thread name")
		socket  = flag.String("socket", "", "control socket path (default: $CODEX_HOME/app-server-control/app-server-control.sock)")
		start   = flag.Bool("start-turn", false, "start a turn with the message instead of only queueing it")
		name    = flag.String("name", "codex-send", "client name recorded in thread metadata")
		timeout = flag.Duration("timeout", 30*time.Second, "give up after this long")
		jsonOut = flag.Bool("json", false, "print results as JSON")
	)
	flag.Usage = usage
	flag.Parse()

	text := strings.Join(flag.Args(), " ")
	if !*list && (*to == "" || text == "") {
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

	if *list {
		return listThreads(ctx, c, *all, *jsonOut)
	}

	thread, err := c.FindThread(ctx, *to)
	if err != nil {
		fmt.Fprintf(os.Stderr, "codex-send: %v\n", err)
		return exitNoTarget
	}

	if *start {
		res, err := c.StartTurn(ctx, codexmsg.TurnStartParams{
			ThreadID: thread.ID,
			Input:    []codexmsg.UserInput{codexmsg.TextInput(text)},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "codex-send: turn/start: %v\n", err)
			return exitError
		}
		if *jsonOut {
			fmt.Println(string(res))
		} else {
			fmt.Printf("Started a turn on thread %s.\n", thread.ID)
		}
		return exitOK
	}

	res, err := c.QueueMessage(ctx, thread.ID, text, codexmsg.NewUUIDv7())
	if err != nil {
		fmt.Fprintf(os.Stderr, "codex-send: %v\n", err)
		return exitError
	}
	if *jsonOut {
		b, _ := json.Marshal(res)
		fmt.Println(string(b))
	} else {
		fmt.Printf("Queued message %s for thread %s.\n", res.QueuedSubmission.ID, thread.ID)
	}
	return exitOK
}

func listThreads(ctx context.Context, c *codexmsg.Client, all, jsonOut bool) int {
	var p codexmsg.ThreadListParams
	if all {
		yes := true
		p.Archived = &yes
	}
	page, err := c.ListThreads(ctx, p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "codex-send: thread/list: %v\n", err)
		return exitError
	}
	if jsonOut {
		b, _ := json.Marshal(page)
		fmt.Println(string(b))
		return exitOK
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "THREAD\tSTATE\tNAME\tCWD\tUPDATED")
	for _, t := range page.Threads {
		state := "not-loaded"
		if t.Loaded() {
			state = t.Status.Type
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", t.ID, state, dash(t.Name), dash(t.Cwd), stamp(t.UpdatedAt))
	}
	w.Flush()
	if len(page.Threads) == 0 {
		fmt.Fprintln(os.Stderr, "no threads on this daemon")
	}
	return exitOK
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// stamp renders a unix-seconds timestamp, which is how the daemon sends
// createdAt and updatedAt.
func stamp(sec int64) string {
	if sec == 0 {
		return "-"
	}
	return time.Unix(sec, 0).Format("2006-01-02 15:04")
}

func usage() {
	fmt.Fprint(os.Stderr, `codex-send — queue a message into a Codex session on this machine

  codex-send --list
  codex-send --to <thread-uuid|name> [flags] <message text>

`)
	flag.PrintDefaults()
}
