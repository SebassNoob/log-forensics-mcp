#!/usr/bin/env bash
set -euo pipefail

# -x matches the process name, not the cmdline: -f would match this script too and kill it.
pkill -x claude-desktop || true
for _ in $(seq 50); do
	pgrep -x claude-desktop >/dev/null || break
	sleep 0.2
done
pkill -9 -x claude-desktop 2>/dev/null || true

setsid nohup claude-desktop >/dev/null 2>&1 </dev/null &
