#!/bin/sh
# Format the notes folder and record when it last ran.
set -eu
mkdir -p "${CLAUDE_PLUGIN_DATA}"
date -u +%Y-%m-%dT%H:%M:%SZ > "${CLAUDE_PLUGIN_DATA}/last-run"
find notes -name '*.md' -type f | sort > /dev/null
