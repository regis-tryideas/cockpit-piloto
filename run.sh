#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec ./bin/python3 app.py
