"""Configuration management for syslog deduplication service."""
import os
import yaml
from typing import Optional
from dataclasses import dataclass, field


def normalize_web_base_path(raw: str) -> str:
    """
    Public URL path prefix for the web UI behind a reverse proxy (no trailing slash).
    Empty string means the app is served at the domain root.
    """
    s = (raw or "").strip()
    if not s:
        return ""
    if "//" in s:
        raise ValueError("WEB_BASE_PATH must not contain '//'")
    if not s.startswith("/"):
        s = "/" + s
    s = s.rstrip("/")
    return s


@dataclass
class SyslogConfig:
    """Syslog server configuration."""
    listen_port: int = 514
    forward_enabled: bool = True
    forward_host: str = ""
    forward_port: int = 514
    use_tcp: bool = False


@dataclass
class NSXTConfig:
    """NSX-T Manager configuration."""
    host: str = ""
    username: str = ""
    password: str = ""
    verify_ssl: bool = True
    cache_ttl: int = 3600  # Cache TTL in seconds
    # Optional: explicit Application section/domain identifiers can be added here later


@dataclass
class InfluxConfig:
    """InfluxDB v1 configuration."""
    enabled: bool = False
    host: str = "localhost"
    port: int = 8086
    database: str = ""
    username: str = ""
    password: str = ""
    measurement: str = "firewall_logs"


@dataclass
class PostgresConfig:
    """PostgreSQL configuration."""
    enabled: bool = False
    host: str = "localhost"
    port: int = 5432
    database: str = ""
    user: str = ""
    password: str = ""
    table: str = "flows"


@dataclass
class WebConfig:
    """Web UI / API server configuration."""
    host: str = "0.0.0.0"
    port: int = 8080
    web_base_path: str = ""


@dataclass
class OidcConfig:
    """Optional OIDC (e.g. Keycloak) for the Web UI / API."""

    enabled: bool = False
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = ""
    scope: str = "openid email profile"
    session_secret: str = ""
    # Verify TLS for HTTPS calls to the issuer (discovery, token endpoint). Set false for internal CAs via OIDC_SSL_VERIFY.
    ssl_verify: bool = True


@dataclass
class Config:
    """Main configuration class."""
    syslog: SyslogConfig
    nsxt: NSXTConfig
    influx: InfluxConfig
    postgres: PostgresConfig
    web: Optional[WebConfig] = None
    oidc: OidcConfig = field(default_factory=OidcConfig)


def load_config(config_path: Optional[str] = None) -> Config:
    """
    Load configuration from YAML file or environment variables.
    
    Args:
        config_path: Path to YAML config file. If None, looks for config.yaml in current directory.
    
    Returns:
        Config object with loaded settings.
    """
    # Try to load from YAML file
    if config_path is None:
        config_path = "config.yaml"
    
    config_data = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Warning: Could not load config file {config_path}: {e}")
    
    # Override with environment variables if present
    syslog_config = SyslogConfig(
        listen_port=int(os.getenv('SYSLOG_LISTEN_PORT', config_data.get('syslog', {}).get('listen_port', 514))),
        forward_enabled=os.getenv(
            'SYSLOG_FORWARD_ENABLED',
            str(config_data.get('syslog', {}).get('forward_enabled', True))
        ).lower() == 'true',
        forward_host=os.getenv('SYSLOG_FORWARD_HOST', config_data.get('syslog', {}).get('forward_host', '')),
        forward_port=int(os.getenv('SYSLOG_FORWARD_PORT', config_data.get('syslog', {}).get('forward_port', 514))),
        use_tcp=os.getenv(
            'SYSLOG_FORWARD_USE_TCP',
            str(config_data.get('syslog', {}).get('use_tcp', False))
        ).lower() == 'true',
    )
    
    nsxt_config = NSXTConfig(
        host=os.getenv('NSXT_HOST', config_data.get('nsxt', {}).get('host', '')),
        username=os.getenv('NSXT_USERNAME', config_data.get('nsxt', {}).get('username', '')),
        password=os.getenv('NSXT_PASSWORD', config_data.get('nsxt', {}).get('password', '')),
        verify_ssl=os.getenv('NSXT_VERIFY_SSL', str(config_data.get('nsxt', {}).get('verify_ssl', True))).lower() == 'true',
        cache_ttl=int(os.getenv('NSXT_CACHE_TTL', config_data.get('nsxt', {}).get('cache_ttl', 3600)))
    )

    influx_cfg = config_data.get('influx', {})
    influx_config = InfluxConfig(
        enabled=os.getenv(
            'INFLUX_ENABLED',
            str(influx_cfg.get('enabled', False))
        ).lower() == 'true',
        host=os.getenv('INFLUX_HOST', influx_cfg.get('host', 'localhost')),
        port=int(os.getenv('INFLUX_PORT', influx_cfg.get('port', 8086))),
        database=os.getenv('INFLUX_DB', influx_cfg.get('database', '')),
        username=os.getenv('INFLUX_USERNAME', influx_cfg.get('username', '')),
        password=os.getenv('INFLUX_PASSWORD', influx_cfg.get('password', '')),
        measurement=os.getenv('INFLUX_MEASUREMENT', influx_cfg.get('measurement', 'firewall_logs')),
    )

    pg_cfg = config_data.get('postgres', {})
    postgres_config = PostgresConfig(
        enabled=os.getenv(
            'PG_ENABLED',
            str(pg_cfg.get('enabled', False))
        ).lower() == 'true',
        host=os.getenv('PG_HOST', pg_cfg.get('host', 'localhost')),
        port=int(os.getenv('PG_PORT', pg_cfg.get('port', 5432))),
        database=os.getenv('PG_DB', pg_cfg.get('database', '')),
        user=os.getenv('PG_USER', pg_cfg.get('user', '')),
        password=os.getenv('PG_PASSWORD', pg_cfg.get('password', '')),
        table=os.getenv('PG_TABLE', pg_cfg.get('table', 'flows')),
    )

    web_cfg = config_data.get('web', {})
    web_base_path_raw = os.getenv('WEB_BASE_PATH', web_cfg.get('base_path', ''))
    web_config = WebConfig(
        host=os.getenv('WEB_HOST', web_cfg.get('host', '0.0.0.0')),
        port=int(os.getenv('WEB_PORT', web_cfg.get('port', 8080))),
        web_base_path=normalize_web_base_path(web_base_path_raw),
    )

    oidc_cfg = config_data.get('oidc', {})
    oidc_config = OidcConfig(
        enabled=os.getenv(
            'OIDC_ENABLED',
            str(oidc_cfg.get('enabled', False)),
        ).lower() == 'true',
        issuer=os.getenv('OIDC_ISSUER', oidc_cfg.get('issuer', '')).strip(),
        client_id=os.getenv('OIDC_CLIENT_ID', oidc_cfg.get('client_id', '')).strip(),
        client_secret=os.getenv('OIDC_CLIENT_SECRET', oidc_cfg.get('client_secret', '')).strip(),
        redirect_uri=os.getenv('OIDC_REDIRECT_URI', oidc_cfg.get('redirect_uri', '')).strip(),
        scope=os.getenv('OIDC_SCOPE', oidc_cfg.get('scope', 'openid email profile')).strip(),
        session_secret=os.getenv(
            'OIDC_SESSION_SECRET',
            os.getenv('WEB_SESSION_SECRET', oidc_cfg.get('session_secret', '')),
        ).strip(),
        ssl_verify=os.getenv(
            'OIDC_SSL_VERIFY',
            str(oidc_cfg.get('ssl_verify', True)),
        ).lower()
        == 'true',
    )

    web_only = os.getenv('WEB_ONLY', '').lower() == 'true'

    # Validate required fields (skip syslog/nsxt when WEB_ONLY)
    if not web_only:
        if syslog_config.forward_enabled and not syslog_config.forward_host:
            raise ValueError("SYSLOG_FORWARD_HOST or syslog.forward_host must be set")
        if not nsxt_config.host:
            raise ValueError("NSXT_HOST or nsxt.host must be set")
        if not nsxt_config.username:
            raise ValueError("NSXT_USERNAME or nsxt.username must be set")
        if not nsxt_config.password:
            raise ValueError("NSXT_PASSWORD or nsxt.password must be set")

    # InfluxDB is optional: only validate database if enabled
    if influx_config.enabled and not influx_config.database:
        raise ValueError("INFLUX_DB or influx.database must be set when Influx is enabled")

    # PostgreSQL: required when web_only; otherwise optional but validated if enabled
    if web_only:
        if not postgres_config.enabled:
            raise ValueError("PG_ENABLED must be true when WEB_ONLY is true")
        if not postgres_config.database:
            raise ValueError("PG_DB or postgres.database must be set")
        if not postgres_config.user:
            raise ValueError("PG_USER or postgres.user must be set")
    elif postgres_config.enabled:
        if not postgres_config.database:
            raise ValueError("PG_DB or postgres.database must be set when Postgres is enabled")
        if not postgres_config.user:
            raise ValueError("PG_USER or postgres.user must be set when Postgres is enabled")

    if oidc_config.enabled:
        if not oidc_config.issuer:
            raise ValueError("OIDC_ISSUER or oidc.issuer must be set when OIDC is enabled")
        if not oidc_config.client_id:
            raise ValueError("OIDC_CLIENT_ID or oidc.client_id must be set when OIDC is enabled")
        if not oidc_config.client_secret:
            raise ValueError("OIDC_CLIENT_SECRET or oidc.client_secret must be set when OIDC is enabled")
        if not oidc_config.redirect_uri:
            raise ValueError("OIDC_REDIRECT_URI or oidc.redirect_uri must be set when OIDC is enabled")
        if not oidc_config.session_secret:
            raise ValueError("OIDC_SESSION_SECRET (or WEB_SESSION_SECRET) must be set when OIDC is enabled")

    return Config(
        syslog=syslog_config,
        nsxt=nsxt_config,
        influx=influx_config,
        postgres=postgres_config,
        web=web_config,
        oidc=oidc_config,
    )

