# harness-transport

Go libraries for talking to the agent harnesses on this machine — the processes
that host a model and the MCP servers it runs.

* `udsmsg` — the observed Claude Code session-to-session messaging protocol
  (`uds-messaging` is our descriptive name): newline-delimited JSON over a Unix
  domain socket, one socket per session. Undocumented by Anthropic, established by observing
  sessions on **Claude Code 2.1.272**, and able to change in any release; see
  `docs/claude-uds-messaging.adoc`.
* `codexmsg` — Codex's app-server protocol: a JSON-RPC dialect over a
  WebSocket on a unix socket. Published by OpenAI; this follows
  `/source/open-source/codex` at **rust-v0.154.0**; see
  `docs/codex-app-server-messaging.adoc`.
* `deliver` — one interface over both, for an MCP server pushing a message
  into the host that launched it.

```
import "github.com/secforge/harness-transport/deliver"
```

## CLI

```
claude-send --list                                  # live sessions
claude-send --list --all                            # include dead ones
claude-send --to <pid> "message"                    # send and wait for an answer
claude-send --to-socket <path> "message"            # address an inbox directly
```

Flags: `--wait reply|replies|idle|status|none` (default `reply`), `--timeout`
(default 5m), `--from-mode prompting|bypass`, `--name`, `--announce`,
`--any-sender`, `--no-auth`, `--no-hint`, `--publish-key`, `--json`,
`--quiet`.

Exit codes: `0` answer received, or a `--wait replies` window that collected at
least one · `1` setup or protocol failure · `3` peer went idle without
answering · `4` timeout, or a window that collected nothing · `5`
denied/expired/refused/dropped · `6` no such session.

### How waiting works

The protocol has no request/response. A `user` frame is fire-and-forget: the
receiver queues it as a prompt and answers in its own transcript. The only
things that come back on the wire are `peer_message_status` and, on
subscription, `peer_idle_notice`.

So `--wait reply` binds an inbox of its own, names it in `from`, and blocks
until the peer sends a message *back* to it. That requires the peer to
cooperate, which is why a short instruction is appended to the message unless
`--no-hint` is given. `peer_idle_notice` is subscribed to as well, so a peer
that finishes its turn without answering ends the wait (exit 3) rather than
hanging until the timeout.

`--wait replies` waits for *many* messages instead of one: it prints each
answer as it arrives and stays for the whole `--timeout`, which is a window
rather than a deadline there — it exits 0 if anything arrived, 4 if nothing
did, and an idle peer no longer ends the wait, since it can be woken again
inside the window.

The inbox lives in a directory every process of this uid can reach, so anyone
could send a frame and be taken for the answer. Only the process actually
addressed is heard; the check is the peer's `SO_PEERCRED` pid, which a sender
cannot forge, unlike the `from` address it asserts. `--any-sender` turns the
filter off, and a target named by an opaque 16-hex socket carries no pid to
compare, in which case everything is heard and the progress line says so.

The inbox is named `<pid>-<8 hex>.sock` — a form the protocol permits — so it
cannot be mistaken for a real session's inbox by anything listing the socket
directory. Socket and key file are removed on exit.

### Being seen as a peer

Two independent things make a message look like it came from a session rather
than from a stranger, and they are easy to confuse:

* **Attribution** — the sender's name and reply address, which travel *inside*
  `message.content` as a `<cross-session-message>` envelope the receiving
  harness parses out. There is no name field on the wire; the receiver never
  looks one up. This is on by default (`--no-hint` sends bare text), so the
  peer sees a named message it can answer with its own SendMessage tool
  instead of a shell command.
* **Discovery** — `--announce <name>` publishes a registry entry at
  `~/.claude/sessions/<pid>.json`, which is what makes us appear in a peer's
  session list as a live session. It is removed on exit. This affects
  listings only; it has nothing to do with attribution.

`--publish-key` publishes a key file for our own inbox so the peer can
authenticate to us when it replies.

The envelope's exact rendering is load-bearing: the receiver re-renders what it
parsed and compares it byte for byte, so a wrong attribute order or an extra
space silently downgrades the whole message to anonymous text. `udsmsg.Wrap`
and `udsmsg.Unwrap` apply that same test; see the doc for the grammar.

## Library

```go
import "github.com/secforge/harness-transport/udsmsg"

// Send.
t, _ := udsmsg.ResolveTarget(pid)            // socket path + published token
c, _ := udsmsg.Dial(ctx, t)                  // presents the auth frame
defer c.Close()
id, _ := c.SendUser(udsmsg.User{Text: "hello", From: srv.Addr()})
c.NotifyWhenIdle(srv.Addr(), id, udsmsg.ModePrompting)

// Receive.
srv, _ := udsmsg.Listen(udsmsg.Config{
    Handler: udsmsg.Handler{
        OnUser: func(ctx context.Context, p *udsmsg.Peer, f *udsmsg.Frame) {
            log.Printf("%s from pid %d (%s)", f.Text(), p.PID, p.Auth)
        },
    },
})
srv.Start(ctx)
defer srv.Close()
```

`Handler` is a struct of optional callbacks — one per message type and control
action, plus `OnUnknown`, `OnDrop` and `OnError`. Every callback receives the
verified `*Peer` (SO_PEERCRED pid, uid, start time, auth identity, `SelfSent`)
and the `*Frame`, whose `Raw` holds the line exactly as received, so fields
this package does not model survive.

The server implements the receiving side in full: 0700 + ownership checks on
the socket directory, key-file publication, the 30 s first-line deadline, the
1 MiB line cap dropping the connection, optional auth enforcement accepting
both peer and child tokens, `session_id` matching, per-line parse-failure
recovery, and trailing-buffer parsing on close.

The three artifact-reply actions are parsed and dispatched, but the claim
semantics are not implemented: they require same-conversation `sessionId` *and*
pid verification that only a real session holds. The library exposes the
verification inputs and leaves the decision to the caller.

## Layout

```
udsmsg/frame.go      wire types, encode/decode, line cap
udsmsg/addr.go       address and socket-name validation, directory checks
udsmsg/discover.go   socket directories, session registry, target resolution
udsmsg/keyfile.go    key file naming (sha256 of the canonical socket path), atomic writes
udsmsg/proc.go       start times, machine id, pid domains, liveness
udsmsg/peer.go       SO_PEERCRED identity
udsmsg/client.go     dialling, auth, sending
udsmsg/server.go     binding, accepting, dispatching
cmd/claude-send/     the CLI
```

## Tests

```
go test ./...
```

Unit tests cover framing, addressing and key files; `TestKeyFileNameMatchesLiveSessions`
checks the digest against every key file Claude Code published on this host.
Integration tests run the library's server against its own client over a
private socket directory, covering auth-required and auth-optional paths,
session-id mismatch, oversize lines, malformed lines, trailing buffers and the
first-line deadline.

Verified live against a real Claude Code session: authenticated send accepted
and injected, and a full round trip — send, peer replies to our inbox, answer
on stdout, exit 0.

## codexmsg — the same job for Codex

`codexmsg` talks to a Codex **app-server daemon**, so one tree can message a
session of either harness. The two protocols are opposites, and the
package exists because almost nothing transfers between them:

| | Claude Code (`udsmsg`) | Codex (`codexmsg`) |
|---|---|---|
| Topology | mesh — one socket per session | hub — one daemon owns every thread |
| Addressing | socket path / pid | thread UUID or name |
| Identity | `SO_PEERCRED` + published token | the `0600` socket |
| Framing | newline-delimited JSON | **WebSocket** over AF_UNIX |
| Attribution | a `<cross-session-message>` envelope inside the prompt | none; the daemon records the client name from `initialize` |
| Spec | none; established by observation | 39 JSON schemas + the Rust source |

Nothing here was inferred: it follows the published source at
`rust-v0.154.0`, the tag matching the installed CLI.

```
codex-send --list                                  # threads on the daemon
codex-send --to <uuid|name> "message"              # queue a message
codex-send --to <uuid|name> --start-turn "message" # queue it and start a turn
```

Three things worth knowing before using it:

* **The socket is WebSocket-framed**, not NDJSON — NDJSON is only the stdio and
  TCP fallback, so writing JSON lines at the socket gets you nowhere.
  `codexmsg` implements the client half of RFC 6455 itself rather than taking a
  dependency; the frame codec is tested against the RFC's own vectors.
* **The dialect is not JSON-RPC 2.0**: there is no `jsonrpc` member on any
  frame. A standard client that stamps one and expects it back will not
  interoperate.
* **The daemon is found under `$CODEX_HOME`** (default `~/.codex`) at
  `app-server-control/app-server-control.sock`. Do not confuse it with
  `ipc/ipc.sock`, which is the IDE-context channel and carries no sessions. A
  `CODEX_HOME` deep enough to push the socket past the 108-byte AF_UNIX limit
  makes the CLI quietly use an embedded server instead of the shared daemon;
  `CheckSocketPath` reports that case rather than failing obscurely.

There is no reply channel. A queued message joins the thread's queue and the
session answers in its own UI — so `codex-send` has no `--wait`, no inbox and
no exit code 3.

Note that `thread/queue/add` is absent from the checked-in JSON schema for
0.154.0 although the CLI sends it: the schema lags the Rust source, so it is
not a complete list of what a daemon answers.

## deliver — push into the harness that launched you

`deliver` is the generalized layer over both transports, for a process that
needs to put a message in front of its own model without waiting to be polled.
The target is the harness that spawned it.

It serves **any** harness client, not only MCP servers — a hook, a shell tool,
any spawned child — because both harnesses identify themselves to their
children at exec:

| Client | Claude Code | Codex |
|---|---|---|
| MCP server | `CLAUDE_CODE_MESSAGING_SOCKET` + child token | `_meta.threadId` on each tool call → `Adopt` |
| hook, shell tool, any child | same environment | not served — see below |

`Open` reads no environment variable for Codex. A thread id is taken only from
the metadata on a tool call, through `Adopt`, and latched once: a second,
different thread disables delivery rather than retargeting. A Codex child that
is not an MCP server sees no tool metadata and so is not served — deliberately,
because the only other candidate is an environment this process was not
necessarily given.

A process **no harness spawned** has nothing inherited and nothing to adopt.
`Available` says so, and that is deliberate: addressing a session you did not
come from is what `udsmsg` and `codexmsg` are for, and what the two CLIs in
`cmd/` do. Keeping that capability out of `deliver` is the point — an MCP
server importing this package has no symbol with which to name another
session.

```go
d := deliver.Open(deliver.WithSenderName("my-mcp-server"))
defer d.Close()

d.Adopt(req.Params.Meta.AdditionalFields) // every inbound MCP request; no-op on Claude

if ok, reason := d.Available(); !ok {
    return reason // a sentence you can show a model, not an error code
}
r, err := d.Deliver(ctx, deliver.Delivery{Cursor: cursor, Body: body, More: more})
```

**There is no address parameter, anywhere.** An MCP server's authority is
derived from the session that spawned it, so a library able to address any
reachable agent would let any MCP server inject text into any other session,
bypassing that session's own user — which matters most for a caller relaying
untrusted content. The target comes from the process relationship instead:

* **Claude Code** — from the environment a harness session hands its children:
  `CLAUDE_CODE_MESSAGING_SOCKET` and `CLAUDE_CODE_MESSAGING_TOKEN`. That second
  one is the *child* token, written to no file and held only by processes the
  session spawned. The *peer* token in `~/.claude/sessions/*.key` is readable by
  any process of the same uid — that one is an address book, and this package
  never touches it.
* **Codex** — from the tool call. The harness stamps `threadId` into each MCP
  request's `_meta`, and `Adopt` latches that once. A second,
  different thread id means two sessions are reaching one MCP process, so the
  backend disables itself permanently rather than retargeting.

The library therefore does not refuse to address other agents. It has nothing
with which to address them.

### What it reports

`Deliver` returns an `Observation`, never a bare nil that means "sent":

| Observation | Meaning | Where |
|---|---|---|
| `ObservedNothing` | bytes written and accepted; arrival unverified | Claude Code, always |
| `ObservedTurnRan` | a turn ran afterwards — correlation, **not** a read | available, unused |
| `ObservedAccepted` | server acknowledged, echo did not match | Codex, degraded |
| `ObservedStored` | server echoed the content and it matched byte for byte | Codex, normal |
| `ObservedConsumed` | the target produced output for this message | — |

Claude Code emits `peer_message_status` only from the hold-approval path, so an
ordinary accepted message is reported on by nobody; `ObservedNothing` is the
strongest honest claim and the package will not dress it up. Codex returns a
receipt that echoes the stored content, which is sha256-compared — so
acknowledgement and integrity are reported separately, because they fail
separately.

Both backends **refuse** an oversize message rather than cutting it, so
`Truncated` is false in every path today; it exists so a backend that ever does
truncate cannot do so silently. `MaxIntactBytes` is a floor: 520,192 bytes on
Claude (the 1 MiB line cap, halved, since JSON escaping can double the payload
and an oversize line costs the whole connection) and 1,044,480 on Codex.

Verified live: a child process delivered into the Claude Code harness session
that spawned it, with the inherited child token, and the message arrived
attributed and whole with its cursor.
