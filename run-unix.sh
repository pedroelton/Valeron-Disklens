#!/usr/bin/env bash
cd "$(dirname "$0")" || exit 1
command -v python3 >/dev/null 2>&1 || { echo "python3 not found"; exit 1; }
exec python3 disklens.py "$@"
