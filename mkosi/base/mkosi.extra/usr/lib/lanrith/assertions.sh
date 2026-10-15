#!/bin/sh
# Sourced by build and boot checks. Assertions explicitly exit on failure,
# including inside conditional function calls where shell errexit is disabled.
# Callers must use public policy patterns only: diagnostics include the pattern.

assertion_failed() {
  printf 'Router assertion failed: %s\n' "$*" >&2
  exit 1
}

reject_match() {
  # grep returns 1 for an inspected input without a match; every other status
  # is either a forbidden match or a failed inspection. Never print input data.
  _router_grep_description=$*
  if [ "${1:-}" = --description ]; then
    _router_grep_description=$2
    shift 2
  fi
  if grep "$@" >/dev/null; then
    assertion_failed "forbidden match: $_router_grep_description"
  else
    _router_grep_status=$?
    [ "$_router_grep_status" -eq 1 ] ||
      assertion_failed "cannot inspect forbidden match (grep $_router_grep_status): $_router_grep_description"
  fi
}

reject_output_match() {
  # Usage: reject_output_match <public invariant name> <ERE pattern> <command...>
  _router_output_description=$1
  _router_output_pattern=$2
  shift 2
  if _router_inspected_output=$("$@"); then
    :
  else
    assertion_failed "cannot inspect $_router_output_description"
  fi
  # A here-document keeps the assertion in this shell and preserves failure
  # even if a caller puts this function in an if/while condition.
  reject_match --description "$_router_output_description" -E -- "$_router_output_pattern" <<EOF
$_router_inspected_output
EOF
}

require_inactive_service() {
  if _router_active_state=$(systemctl show --property=ActiveState --value "$1"); then
    :
  else
    assertion_failed "cannot inspect service state: $1"
  fi
  [ "$_router_active_state" = inactive ] ||
    assertion_failed "service must be inactive: $1"
}

require_absent_link() {
  # Listing all links succeeds when the named link is absent; a failed ip
  # invocation must not stand in for proof that an interface was removed.
  reject_output_match "absent interface $1" "^[0-9]+: $1(@[^:]+)?: " ip -o link show
}
