"""NSX-T Manager API client for IP-to-group lookups."""
import logging
import time
from typing import Optional, Dict, List, Any
import requests
from requests.auth import HTTPBasicAuth
from config import NSXTConfig


logger = logging.getLogger(__name__)


class NSXTClient:
    """Client for NSX-T Manager API to lookup IP addresses in groups."""
    
    def __init__(self, config: NSXTConfig):
        """
        Initialize NSX-T client.
        
        Args:
            config: NSXTConfig object with connection details
        """
        self.config = config
        self.base_url = f"https://{config.host}"
        self.auth = HTTPBasicAuth(config.username, config.password)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.verify = config.verify_ssl
        
        # Per-IP cache for results
        self._ip_cache: Dict[str, Optional[List[str]]] = {}
        self._cache_timestamps: Dict[str, float] = {}

        # Prefetched groups data (for batch/local lookup)
        self._groups_last_refresh: float = 0.0
        self._groups: List[Dict[str, Any]] = []
        self._last_refresh_attempt: float = 0.0
    
    def _get_cache_key(self, ip: str) -> str:
        """Generate cache key for IP address."""
        return ip
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cache entry is still valid."""
        if cache_key not in self._cache_timestamps:
            return False
        age = time.time() - self._cache_timestamps[cache_key]
        return age < self.config.cache_ttl
    
    def _get_from_cache(self, ip: str) -> Optional[List[str]]:
        """Get group names from cache if valid."""
        cache_key = self._get_cache_key(ip)
        if self._is_cache_valid(cache_key):
            return self._ip_cache.get(cache_key)
        return None
    
    def _store_in_cache(self, ip: str, groups: Optional[List[str]]):
        """Store group names in cache."""
        cache_key = self._get_cache_key(ip)
        self._ip_cache[cache_key] = groups
        self._cache_timestamps[cache_key] = time.time()

    # -------- Batch / precomputed group loading --------

    def _refresh_groups_if_needed(self):
        """
        Refresh the in-memory list of NSX groups if cache_ttl has expired.

        This precomputes group membership structures so lookups don't hit
        the NSX API for every single IP.
        """
        now = time.time()

        # Hard throttle: don't attempt a refresh more often than this interval,
        # regardless of cache_ttl or errors. This keeps us well under NSX rate
        # and concurrency limits for group downloads.
        MIN_REFRESH_INTERVAL = 60  # seconds
        if now - self._last_refresh_attempt < MIN_REFRESH_INTERVAL:
            return
        self._last_refresh_attempt = now

        if self._groups and (now - self._groups_last_refresh) < self.config.cache_ttl:
            return

        try:
            # Use domain-specific groups endpoint (default domain)
            groups_url = f"{self.base_url}/policy/api/v1/infra/domains/default/groups"
            response = self.session.get(groups_url, timeout=15)
            response.raise_for_status()
            groups_data = response.json()

            groups: List[Dict[str, Any]] = []

            for group in groups_data.get("results", []):
                group_id = group.get("id", "")
                group_path = group.get("path", "")
                if not group_id:
                    continue

                detail_url = (
                    f"{self.base_url}/policy/api/v1/infra/domains/default/groups/{group_id}"
                )
                try:
                    detail_resp = self.session.get(detail_url, timeout=15)
                    detail_resp.raise_for_status()
                    detail = detail_resp.json()
                    detail["path"] = group_path  # ensure path is present
                    groups.append(detail)
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Failed to get group detail for {group_id}: {e}")
                    continue

                # Soft rate limit within a refresh: sleep a bit between
                # detail requests so we don't exceed NSX per-client RPS.
                time.sleep(0.05)  # ~20 detail requests per second max

            self._groups = groups
            self._groups_last_refresh = now
            logger.info(f"Refreshed NSX groups cache, loaded {len(groups)} groups")
            # Write full group/membership details to log file for debugging/inspection
            logger.debug("NSX groups detail: %r", self._groups)

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to refresh NSX groups from NSX-T: {e}")
            # don't blow up; leave existing groups in place if any
    
    def lookup_ip_groups(self, ip_address: str) -> Optional[List[str]]:
        """
        Lookup which NSX groups contain the given IP address.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            List of group names (paths) that contain this IP, or None if lookup fails
        """
        # Check per-IP cache first
        cached = self._get_from_cache(ip_address)
        if cached is not None:
            return cached
        
        # Ensure we have a fresh in-memory group list
        self._refresh_groups_if_needed()

        matching_paths: List[str] = []
        for group_detail in self._groups:
            if self._ip_matches_group(ip_address, group_detail):
                path = group_detail.get("path") or group_detail.get("display_name") or ""
                if path:
                    matching_paths.append(path)

        # Store in cache (even if empty list) so repeated lookups are cheap
        self._store_in_cache(ip_address, matching_paths if matching_paths else [])
        return matching_paths
    
    def _ip_matches_group(self, ip: str, group_detail: dict) -> bool:
        """
        Check if an IP address matches a group's membership criteria.
        
        Args:
            ip: IP address to check
            group_detail: Group detail dictionary from NSX-T API
            
        Returns:
            True if IP matches group membership
        """
        # Check expression criteria (can be a list or a single expression)
        expression = group_detail.get('expression', [])
        if expression:
            # Handle both list and single expression
            expressions = expression if isinstance(expression, list) else [expression]
            for expr in expressions:
                if isinstance(expr, dict) and self._ip_matches_expression(ip, expr):
                    return True
        
        # Check IP address sets (direct IP addresses)
        ip_addresses = group_detail.get('ip_addresses', [])
        if isinstance(ip_addresses, list) and ip in ip_addresses:
            return True
        
        # Check IP ranges (CIDR notation)
        ip_ranges = group_detail.get('ip_ranges', [])
        if isinstance(ip_ranges, list):
            for ip_range in ip_ranges:
                if isinstance(ip_range, str) and self._ip_in_range(ip, ip_range):
                    return True
        
        return False
    
    def _ip_matches_expression(self, ip: str, expression: dict) -> bool:
        """Check if IP matches an expression criteria."""
        # This is a simplified check - NSX-T expressions can be complex
        # For now, check common patterns like IPAddressExpression
        expr_type = expression.get('resource_type', '')
        if expr_type == 'IPAddressExpression':
            ip_addresses = expression.get('ip_addresses', [])
            return ip in ip_addresses
        return False
    
    def _ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if IP is in a CIDR range."""
        try:
            from ipaddress import ip_address, ip_network
            ip_obj = ip_address(ip)
            network = ip_network(ip_range, strict=False)
            return ip_obj in network
        except (ValueError, ImportError):
            return False
    
    def clear_cache(self):
        """Clear the IP-to-group cache."""
        self._ip_cache.clear()
        self._cache_timestamps.clear()

