#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
if [ ! -f .env ]; then cp .env.example .env; fi
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m app.create_admin
echo
printf 'CloudAuth is starting. Open http://127.0.0.1:8000 in your browser.\n'
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
