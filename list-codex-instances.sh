#!/usr/bin/env bash
# Lists running Codex CLI/app-server processes with their working directory
# and, where a matching local session log can be found, the session's
# thread/session ID and thread name.
#
# Matching heuristic: Codex CLI session logs (~/.codex/sessions/**/*.jsonl)
# start with a "session_meta" record that carries the cwd the session was
# started/resumed in. For each running "codex"/"codex-code-mode-host"
# process we look for session logs whose recorded cwd matches the process's
# current cwd, then pick the most recently modified one as the best guess
# for "the session this process is currently serving". This is a heuristic,
# not a guaranteed 1:1 mapping (e.g. the background app-server can serve
# many sessions/cwds at once), so results for such processes may be blank
# or approximate.

set -u -o pipefail

CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
SESSIONS_DIR="$CODEX_HOME/sessions"
SESSION_INDEX="$CODEX_HOME/session_index.jsonl"

command -v jq >/dev/null 2>&1 || { echo "error: jq is required but not found" >&2; exit 1; }

# id -> thread_name (last entry for a given id wins)
declare -A THREAD_NAME=()
if [[ -f "$SESSION_INDEX" ]]; then
  while IFS=$'\t' read -r id name; do
    [[ -n "$id" ]] && THREAD_NAME["$id"]="$name"
  done < <(jq -r 'select(.id) | [.id, (.thread_name // "")] | @tsv' "$SESSION_INDEX" 2>/dev/null)
fi

# Build cwd -> "mtime<TAB>session_id" for the most-recently-modified session
# log per cwd, by scanning each log's first (session_meta) line.
declare -A CWD_BEST_MTIME=()
declare -A CWD_BEST_ID=()
if [[ -d "$SESSIONS_DIR" ]]; then
  while IFS= read -r -d '' f; do
    meta=$(head -n1 -- "$f" 2>/dev/null | jq -c 'select(.type=="session_meta") | {id: .payload.session_id, cwd: .payload.cwd}' 2>/dev/null)
    [[ -z "$meta" || "$meta" == "null" ]] && continue
    s_id=$(jq -r '.id // empty' <<<"$meta")
    s_cwd=$(jq -r '.cwd // empty' <<<"$meta")
    [[ -z "$s_id" || -z "$s_cwd" ]] && continue
    mtime=$(stat -c '%Y' -- "$f" 2>/dev/null) || continue
    if [[ -z "${CWD_BEST_MTIME[$s_cwd]:-}" || "$mtime" -gt "${CWD_BEST_MTIME[$s_cwd]}" ]]; then
      CWD_BEST_MTIME["$s_cwd"]="$mtime"
      CWD_BEST_ID["$s_cwd"]="$s_id"
    fi
  done < <(find "$SESSIONS_DIR" -type f -name '*.jsonl' -print0 2>/dev/null)
fi

printf '%-8s %-10s %-45s %-38s %s\n' "PID" "ROLE" "CWD" "THREAD ID" "SESSION NAME"

# Enumerate candidate codex processes: comm exactly "codex" or "codex-code-mode-host".
while IFS=$'\t' read -r pid comm; do
  [[ -r "/proc/$pid/cwd" ]] || continue
  cwd=$(readlink -f "/proc/$pid/cwd" 2>/dev/null) || cwd="?"
  args=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)

  role="$comm"
  case "$args" in
    *"app-server"*) role="app-server" ;;
    *"resume"*)     role="resume" ;;
    *"codex-code-mode-host"*) role="code-mode-host" ;;
  esac

  thread_id="${CWD_BEST_ID[$cwd]:-}"
  session_name=""
  if [[ -n "$thread_id" ]]; then
    session_name="${THREAD_NAME[$thread_id]:-}"
  fi

  printf '%-8s %-10s %-45s %-38s %s\n' \
    "$pid" "$role" "$cwd" "${thread_id:--}" "${session_name:--}"
done < <(ps -eo pid=,comm= | awk '$2=="codex" || $2 ~ /^codex-code-mode/ {print $1"\t"$2}')
