"""Web API and UI for listing firewall rules (read-only). Run with: WEB_ONLY=true uvicorn web:app --host 0.0.0.0 --port 8080"""
import json
import os
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from pydantic import BaseModel

from config import load_config
from postgres_client import PostgresClient
from nsxt_client import NSXTClient

# Allow running web server without syslog/NSXT config
if os.getenv("WEB_ONLY", "").lower() != "true":
    os.environ.setdefault("WEB_ONLY", "true")

config = load_config()
pg = PostgresClient(config.postgres)
nsxt: Optional[NSXTClient]
try:
    # NSX-T is optional for read-only UI; only initialize client when host is configured.
    nsxt = NSXTClient(config.nsxt) if config.nsxt.host else None
except Exception:
    nsxt = None

static_dir = Path(__file__).resolve().parent / "static"


def parse_protocols_csv(raw: str) -> List[str]:
    return [p.strip().upper() for p in (raw or "").split(",") if p.strip()]


def parse_result(raw: str) -> str:
    return (raw or "").strip().lower()


def create_inner_app() -> FastAPI:
    """Inner FastAPI app (routes at /, /api, /static, /auth)."""
    inner = FastAPI(title="Firewall rules", description="List and filter firewall flows for NSX-T")

    if static_dir.is_dir():
        inner.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    if config.oidc.enabled:
        from starlette.middleware.sessions import SessionMiddleware

        from oidc_routes import OIDCAuthMiddleware, init_oidc, router as oidc_router

        init_oidc(config.oidc, web_base_path=config.web.web_base_path)
        inner.add_middleware(OIDCAuthMiddleware, oidc_enabled=True)
        inner.add_middleware(
            SessionMiddleware,
            secret_key=config.oidc.session_secret,
            same_site="lax",
            https_only=False,
        )
        inner.include_router(oidc_router)

    @inner.get("/api/auth/status")
    def api_auth_status(request: Request):
        """Public: OIDC flag and whether the session has a logged-in user (for login/logout UI)."""
        if not config.oidc.enabled:
            return {"oidc_enabled": False, "authenticated": False, "base_path": config.web.web_base_path}
        session = getattr(request, "session", None)
        authenticated = bool(session and session.get("user"))
        return {
            "oidc_enabled": True,
            "authenticated": authenticated,
            "base_path": config.web.web_base_path,
        }

    @inner.get("/api/groups")
    def api_groups(
        src_ip: str = Query("", description="Filter source groups by exact source IP"),
        dest_ip: str = Query("", description="Filter destination groups by exact destination IP"),
    ):
        """Distinct source_group and dest_group for dropdowns."""
        return pg.get_groups(src_ip=src_ip or None, dest_ip=dest_ip or None)

    @inner.get("/api/rules")
    def api_rules(
        source_group: str = Query("", description="Filter by source group"),
        dest_group: str = Query("", description="Filter by dest group"),
        hours: int = Query(0, ge=0, description="Only include rules from the last N hours; 0 = all time"),
        src_ip: str = Query("", description="Filter by source IP (substring match)"),
        dest_ip: str = Query("", description="Filter by dest IP (substring match)"),
        dest_port: str = Query("", description="Filter by destination port (text)"),
        protocols: str = Query("", description="Comma-separated protocol filter (e.g. TCP,UDP,FIN,RST)"),
        result: str = Query("", description="Filter by result (pass/drop)"),
    ):
        """Flat list of rules; optional filter by source_group, dest_group."""
        return pg.get_rules(
            source_group=source_group or None,
            dest_group=dest_group or None,
            hours=hours or 0,
            src_ip=src_ip or None,
            dest_ip=dest_ip or None,
            dest_port=dest_port or None,
            protocols=parse_protocols_csv(protocols),
            result=parse_result(result),
        )

    @inner.get("/api/rules/grouped")
    def api_rules_grouped(
        source_group: str = Query("", description="Filter by source group"),
        dest_group: str = Query("", description="Filter by dest group"),
        hours: int = Query(0, ge=0, description="Only include rules from the last N hours; 0 = all time"),
        src_ip: str = Query("", description="Filter by source IP (substring match)"),
        dest_ip: str = Query("", description="Filter by dest IP (substring match)"),
        dest_port: str = Query("", description="Filter by destination port (text)"),
        protocols: str = Query("", description="Comma-separated protocol filter (e.g. TCP,UDP,FIN,RST)"),
        result: str = Query("", description="Filter by result (pass/drop)"),
    ):
        """Rules grouped by (source_group, dest_group) with aggregated dest_ports."""
        return pg.get_rules_grouped(
            source_group=source_group or None,
            dest_group=dest_group or None,
            hours=hours or 0,
            src_ip=src_ip or None,
            dest_ip=dest_ip or None,
            dest_port=dest_port or None,
            protocols=parse_protocols_csv(protocols),
            result=parse_result(result),
        )

    @inner.get("/api/protocols")
    def api_protocols():
        """Distinct protocol values for the web UI dropdown."""
        return {"protocols": pg.get_protocols()}

    class CreateRuleRequest(BaseModel):
        source_group: str
        dest_group: str
        policy_id: str
        direction: str
        service_id: str
        ip_protocol: str = "IPV4"
        port: Optional[int] = None
        protocol: Optional[str] = None
        comment: Optional[str] = None
        policy_name: Optional[str] = None

    @inner.get("/api/nsx/policies")
    def api_nsx_policies():
        """List NSX-T security policies in the Application section for the dropdown."""
        if not nsxt:
            raise HTTPException(status_code=503, detail="NSX-T Manager is not configured for this server")
        policies = nsxt.list_application_policies()
        return JSONResponse(policies)

    @inner.get("/api/nsx/services")
    def api_nsx_services():
        """List NSX-T services for the dropdown."""
        if not nsxt:
            raise HTTPException(status_code=503, detail="NSX-T Manager is not configured for this server")
        services = nsxt.list_services()
        return JSONResponse(services)

    @inner.post("/api/nsx/rules")
    def api_nsx_create_rule(req: CreateRuleRequest):
        """
        Create a new NSX-T distributed firewall rule in the Application section.

        - Rule name: sourcegroup_destinationgroup_service_direction
        - Logging enabled
        - Rule created disabled
        - Applied-to depends on direction:
            in     -> destination group
            out    -> source group
            in/out -> both source and destination groups
        """
        if not nsxt:
            raise HTTPException(status_code=503, detail="NSX-T Manager is not configured for this server")

        source_group = (req.source_group or "").strip()
        dest_group = (req.dest_group or "").strip()
        policy_id = (req.policy_id or "").strip()
        policy_name = (req.policy_name or "").strip()
        direction_raw = (req.direction or "").strip().lower()
        service_id = (req.service_id or "").strip()
        ip_protocol = (req.ip_protocol or "IPV4").strip().upper()
        comment = (req.comment or "").strip()

        if not source_group or not dest_group or not policy_id or not direction_raw or not service_id:
            raise HTTPException(status_code=400, detail="source_group, dest_group, policy_id, direction, and service_id are required")

        if direction_raw not in {"in", "out", "in/out"}:
            raise HTTPException(status_code=400, detail="direction must be one of: in, out, in/out")

        if ip_protocol not in {"IPV4", "IPV6", "IPV4_IPV6"}:
            raise HTTPException(status_code=400, detail="ip_protocol must be one of: IPV4, IPV6, IPV4_IPV6")

        # Map to NSX-T direction constants
        if direction_raw == "in":
            nsx_direction = "IN"
            applied_to = [dest_group]
        elif direction_raw == "out":
            nsx_direction = "OUT"
            applied_to = [source_group]
        else:
            nsx_direction = "IN_OUT"
            applied_to = [source_group, dest_group]

        # Derive a human-readable service name for the rule name from services list
        service_name = service_id
        try:
            services = nsxt.list_services()
            for svc in services:
                if svc.get("id") == service_id:
                    service_name = svc.get("name") or svc.get("display") or service_id
                    break
        except Exception:
            # Fall back to service_id if listing fails
            service_name = service_id

        direction_for_name = direction_raw.replace("/", "-")
        rule_name = f"{source_group}_{dest_group}_{service_name}_{direction_for_name}"
        label = f"{policy_name}_{rule_name}" if policy_name else rule_name

        try:
            result = nsxt.create_firewall_rule(
                policy_id=policy_id,
                rule_name=rule_name,
                direction=nsx_direction,
                source_group_names=[source_group],
                dest_group_names=[dest_group],
                applied_to_group_names=applied_to,
                service_id=service_id,
                ip_protocol=ip_protocol,
                description=comment or None,
                label=label,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Failed to create NSX-T firewall rule: {e}")

        return JSONResponse({"rule_name": rule_name, "nsx_response": result})

    @inner.get("/", response_class=HTMLResponse)
    def index():
        """Serve the firewall rules UI with optional WEB_BASE_PATH injection."""
        index_path = static_dir / "index.html"
        if not index_path.exists():
            return HTMLResponse(
                "<p>Static files not found. Create <code>static/index.html</code>.</p>",
                status_code=404,
            )
        html = index_path.read_text(encoding="utf-8")
        inject = f"<script>window.__BASE_PATH__ = {json.dumps(config.web.web_base_path)};</script>\n"
        if "<head>" in html:
            html = html.replace("<head>", "<head>\n" + inject, 1)
        else:
            html = inject + html
        return HTMLResponse(content=html, media_type="text/html")

    return inner


if config.web.web_base_path:
    app = FastAPI()
    app.mount(config.web.web_base_path, create_inner_app())
else:
    app = create_inner_app()
