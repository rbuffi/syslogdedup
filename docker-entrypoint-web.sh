#!/bin/sh
set -e
exec uvicorn web:app --host 0.0.0.0 --port "${WEB_PORT:-8080}"
