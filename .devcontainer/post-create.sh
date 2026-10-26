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


# The oasa.toml tool: python3 .oasa/oasa_toml.py run --markdown
mkdir -p .oasa
if ! curl -fsSL https://raw.githubusercontent.com/joinoasa/website/main/tools/oasa-files/oasa_toml.py -o .oasa/oasa_toml.py; then
  echo "warning: could not download oasa_toml.py; get it later (see https://joinoasa.org/docs/oasa-files/#the-tool)" >&2
fi

# Everything else is [setup].steps in oasa.toml (venv, build, packages): the single source of truth.
if [ -f .oasa/oasa_toml.py ]; then python3 .oasa/oasa_toml.py setup; else echo "warning: run setup later: python3 .oasa/oasa_toml.py setup" >&2; fi
echo "Ready. Run the checks: python3 .oasa/oasa_toml.py run --markdown"
