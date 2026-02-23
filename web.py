"""Web API and UI for listing firewall rules (read-only). Run with: WEB_ONLY=true uvicorn web:app --host 0.0.0.0 --port 8080"""
import os
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from config import load_config
from postgres_client import PostgresClient

# Allow running web server without syslog/NSXT config
if os.getenv("WEB_ONLY", "").lower() != "true":
    os.environ.setdefault("WEB_ONLY", "true")

config = load_config()
pg = PostgresClient(config.postgres)

app = FastAPI(title="Firewall rules", description="List and filter firewall flows for NSX-T")
static_dir = Path(__file__).resolve().parent / "static"
if static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/api/groups")
def api_groups():
    """Distinct source_group and dest_group for dropdowns."""
    return pg.get_groups()


@app.get("/api/rules")
def api_rules(
    source_group: str = Query("", description="Filter by source group"),
    dest_group: str = Query("", description="Filter by dest group"),
):
    """Flat list of rules; optional filter by source_group, dest_group."""
    return pg.get_rules(source_group=source_group or None, dest_group=dest_group or None)


@app.get("/api/rules/grouped")
def api_rules_grouped(
    source_group: str = Query("", description="Filter by source group"),
    dest_group: str = Query("", description="Filter by dest group"),
):
    """Rules grouped by (source_group, dest_group) with aggregated dest_ports."""
    return pg.get_rules_grouped(source_group=source_group or None, dest_group=dest_group or None)


@app.get("/", response_class=HTMLResponse)
def index():
    """Serve the firewall rules UI."""
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return HTMLResponse(
        "<p>Static files not found. Create <code>static/index.html</code>.</p>",
        status_code=404,
    )
