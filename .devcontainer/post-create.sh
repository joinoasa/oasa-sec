#!/usr/bin/env bash
# One-time setup for the dev container. Safe to run again.
# Installs the tools the checks in oasa.toml need. The first run takes a few minutes
# (cargo-deny and cargo-audit compile from source).
set -euo pipefail
cd "$(dirname "$0")/.."

rustup component add rustfmt clippy
for tool in cargo-deny cargo-audit; do
  command -v "$tool" >/dev/null || cargo install --locked "$tool"
done

# Python venv with pymavlink for scripts/e2e.sh and scripts/link-e2e.sh (the checks point PYTHON at it).
python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet pymavlink

# The oasa.toml tool: python3 .oasa/oasa_toml.py run --markdown
mkdir -p .oasa
if ! curl -fsSL https://raw.githubusercontent.com/joinoasa/website/main/tools/oasa-files/oasa_toml.py -o .oasa/oasa_toml.py; then
  echo "warning: could not download oasa_toml.py; get it later (see https://joinoasa.org/docs/oasa-files/#the-tool)" >&2
fi

cargo fetch --locked
echo "Ready. Run the checks: python3 .oasa/oasa_toml.py run --markdown"
