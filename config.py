"""Configuration management for syslog deduplication service."""
import os
import yaml
from typing import Optional
from dataclasses import dataclass


@dataclass
class SyslogConfig:
    """Syslog server configuration."""
    listen_port: int = 514
    forward_host: str = ""
    forward_port: int = 514


@dataclass
class NSXTConfig:
    """NSX-T Manager configuration."""
    host: str = ""
    username: str = ""
    password: str = ""
    verify_ssl: bool = True
    cache_ttl: int = 3600  # Cache TTL in seconds


@dataclass
class Config:
    """Main configuration class."""
    syslog: SyslogConfig
    nsxt: NSXTConfig


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
        forward_host=os.getenv('SYSLOG_FORWARD_HOST', config_data.get('syslog', {}).get('forward_host', '')),
        forward_port=int(os.getenv('SYSLOG_FORWARD_PORT', config_data.get('syslog', {}).get('forward_port', 514)))
    )
    
    nsxt_config = NSXTConfig(
        host=os.getenv('NSXT_HOST', config_data.get('nsxt', {}).get('host', '')),
        username=os.getenv('NSXT_USERNAME', config_data.get('nsxt', {}).get('username', '')),
        password=os.getenv('NSXT_PASSWORD', config_data.get('nsxt', {}).get('password', '')),
        verify_ssl=os.getenv('NSXT_VERIFY_SSL', str(config_data.get('nsxt', {}).get('verify_ssl', True))).lower() == 'true',
        cache_ttl=int(os.getenv('NSXT_CACHE_TTL', config_data.get('nsxt', {}).get('cache_ttl', 3600)))
    )
    
    # Validate required fields
    if not syslog_config.forward_host:
        raise ValueError("SYSLOG_FORWARD_HOST or syslog.forward_host must be set")
    if not nsxt_config.host:
        raise ValueError("NSXT_HOST or nsxt.host must be set")
    if not nsxt_config.username:
        raise ValueError("NSXT_USERNAME or nsxt.username must be set")
    if not nsxt_config.password:
        raise ValueError("NSXT_PASSWORD or nsxt.password must be set")
    
    return Config(syslog=syslog_config, nsxt=nsxt_config)

