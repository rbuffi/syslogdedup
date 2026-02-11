"""NSX-T Manager API client for IP-to-group lookups."""
import logging
import time
from typing import Optional, Dict, List
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
        
        # Cache for IP-to-group mappings
        self._ip_cache: Dict[str, Optional[List[str]]] = {}
        self._cache_timestamps: Dict[str, float] = {}
    
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
    
    def lookup_ip_groups(self, ip_address: str) -> Optional[List[str]]:
        """
        Lookup which NSX groups contain the given IP address.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            List of group names (paths) that contain this IP, or None if lookup fails
        """
        # Check cache first
        cached = self._get_from_cache(ip_address)
        if cached is not None:
            return cached
        
        try:
            # Use the Policy API to find groups containing this IP
            # First, get all groups
            groups_url = f"{self.base_url}/policy/api/v1/infra/groups"
            response = self.session.get(groups_url, timeout=10)
            response.raise_for_status()
            
            groups_data = response.json()
            matching_groups = []
            
            # Check each group for IP membership
            for group in groups_data.get('results', []):
                group_path = group.get('path', '')
                group_id = group.get('id', '')
                
                # Get group details including membership criteria
                group_detail_url = f"{self.base_url}/policy/api/v1/infra/groups/{group_id}"
                try:
                    detail_response = self.session.get(group_detail_url, timeout=10)
                    detail_response.raise_for_status()
                    group_detail = detail_response.json()
                    
                    # Check if IP matches any membership criteria
                    if self._ip_matches_group(ip_address, group_detail):
                        matching_groups.append(group_path)
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Failed to get details for group {group_id}: {e}")
                    continue
            
            # Store in cache (even if empty list)
            self._store_in_cache(ip_address, matching_groups if matching_groups else [])
            return matching_groups if matching_groups else []
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to lookup IP {ip_address} in NSX-T: {e}")
            # Cache None to avoid repeated failed lookups
            self._store_in_cache(ip_address, None)
            return None
    
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

