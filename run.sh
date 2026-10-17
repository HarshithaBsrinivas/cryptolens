#!/usr/bin/env bash
# Mac / Linux launcher: creates a virtual environment, installs packages, starts CryptoLens.
set -e
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
. .venv/bin/activate
pip install -q -r requirements.txt
python app.py
