#!/usr/bin/env bash
# FIMS - File Integrity Monitoring System
# Interactive Menu Launcher (Select options without typing commands)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -x "./fims" ]; then
    echo "Compiling FIMS..."
    make -j"$(nproc)"
fi

exec ./fims menu "$@"
