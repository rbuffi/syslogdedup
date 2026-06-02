"""NSX-T Manager API client for IP-to-group lookups."""
import logging
import re
import threading
import time
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Literal, Optional, Dict, List, Any, Tuple

MembershipLookup = Literal["cache", "live"]

import requests
from requests.auth import HTTPBasicAuth

from config import NSXTConfig


logger = logging.getLogger(__name__)

# Structured tag (scope "label") for rules created by this app; separate from payload["tag"] (log/CLI).
CREATED_BY_TOOL_LABEL_TAG = "Regel aangemaakt door NSX microsegmentatie tool"


class NSXTClient:
    """Client for NSX-T Manager API to lookup IP addresses in groups."""
    
    def __init__(self, config: NSXTConfig, *, ingest_mode: bool = False):
        """
        Initialize NSX-T client.
        
        Args:
            config: NSXTConfig object with connection details
            ingest_mode: If True, syslog ingest uses bulk-cached groups only (no per-IP NSX refresh).
        """
        self.ingest_mode = ingest_mode
        self.config = config
        self.base_url = f"https://{config.host}"
        self.auth = HTTPBasicAuth(config.username, config.password)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.verify = config.verify_ssl
        
        # Per-IP cache for results (UI / lookup_ip_groups)
        self._ip_cache: Dict[str, Optional[List[str]]] = {}
        self._cache_timestamps: Dict[str, float] = {}

        # Per-IP cache for syslog ingest (primary_groups, all_groups)
        self._ingest_ip_cache: Dict[str, Tuple[Optional[List[str]], Optional[List[str]]]] = {}
        self._ingest_cache_timestamps: Dict[str, float] = {}

        # Prefetched groups data (for batch/local lookup)
        self._groups_last_refresh: float = 0.0
        self._groups: List[Dict[str, Any]] = []
        self._last_refresh_attempt: float = 0.0
        # Map for fast group lookup by path/id (for nested group resolution)
        self._groups_by_path: Dict[str, Dict[str, Any]] = {}
        self._groups_by_id: Dict[str, Dict[str, Any]] = {}
        self._catalog_lock = threading.Lock()

    def _nsx_get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        timeout: float = 30,
    ):
        """
        HTTP GET to NSX. Worker threads use a fresh request (not shared Session)
        because requests.Session is not guaranteed thread-safe.
        """
        if threading.current_thread() is threading.main_thread():
            return self.session.get(url, params=params, timeout=timeout)
        return requests.get(
            url,
            params=params,
            auth=self.auth,
            verify=self.config.verify_ssl,
            timeout=timeout,
        )

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

    def _is_ingest_cache_valid(self, cache_key: str) -> bool:
        if cache_key not in self._ingest_cache_timestamps:
            return False
        age = time.time() - self._ingest_cache_timestamps[cache_key]
        return age < self.config.cache_ttl

    def _get_from_ingest_cache(
        self, ip: str
    ) -> Optional[Tuple[Optional[List[str]], Optional[List[str]]]]:
        cache_key = self._get_cache_key(ip)
        if self._is_ingest_cache_valid(cache_key):
            return self._ingest_ip_cache.get(cache_key)
        return None

    def _store_in_ingest_cache(
        self,
        ip: str,
        result: Tuple[Optional[List[str]], Optional[List[str]]],
    ) -> None:
        cache_key = self._get_cache_key(ip)
        self._ingest_ip_cache[cache_key] = result
        self._ingest_cache_timestamps[cache_key] = time.time()

    def _clear_ingest_ip_cache(self) -> None:
        self._ingest_ip_cache.clear()
        self._ingest_cache_timestamps.clear()

    def refresh_ingest_catalog(self, force: bool = False) -> None:
        """
        Reload the in-memory group catalog from NSX (detail + all IP members).
        Intended for syslog: call at startup and on a fixed interval, not per log line.
        """
        before = self._groups_last_refresh
        self._refresh_groups_if_needed(force=force)
        if self._groups_last_refresh > before or (force and self._groups):
            self._clear_ingest_ip_cache()

    def lookup_ingest_ip_groups(
        self, ip_address: str
    ) -> Tuple[Optional[List[str]], Optional[List[str]]]:
        """
        Resolve primary (smallest) and all matching group names using only the
        in-memory catalog. Does not contact NSX; catalog must be refreshed separately.
        """
        cached = self._get_from_ingest_cache(ip_address)
        if cached is not None:
            return cached

        matching: List[Tuple[str, int]] = []
        for group_detail in self._groups:
            if self._ip_matches_group(
                ip_address, group_detail, membership_lookup="cache"
            ):
                name = self._extract_group_name(group_detail)
                if name:
                    matching.append((name, int(group_detail.get("member_count", 999999))))

        if not matching:
            result: Tuple[Optional[List[str]], Optional[List[str]]] = (None, None)
            self._store_in_ingest_cache(ip_address, result)
            return result

        best_count_by_name: Dict[str, int] = {}
        for name, count in matching:
            if name not in best_count_by_name or count < best_count_by_name[name]:
                best_count_by_name[name] = count
        all_groups = [
            name
            for name, _count in sorted(best_count_by_name.items(), key=lambda nc: (nc[1], nc[0]))
        ]

        min_count = min(count for _, count in matching)
        primary = sorted({name for name, count in matching if count == min_count})
        result = (primary or None, all_groups or None)
        self._store_in_ingest_cache(ip_address, result)
        return result

    # -------- Batch / precomputed group loading --------

    def _refresh_groups_if_needed(self, force: bool = False):
        """
        Refresh the in-memory list of NSX groups if cache_ttl has expired.

        This precomputes group membership structures so lookups don't hit
        the NSX API for every single IP.

        Args:
            force: If True, bypass TTL/min-interval guards and refetch from NSX
                (explicit UI refresh). ``_last_refresh_attempt`` is only updated
                after a successful fetch so a failed load can retry immediately.
        """
        now = time.time()
        MIN_REFRESH_INTERVAL = 60  # seconds

        if not force:
            if self._groups and (now - self._last_refresh_attempt) < MIN_REFRESH_INTERVAL:
                return
            if self._groups and (now - self._groups_last_refresh) < self.config.cache_ttl:
                return

        try:
            # Use domain-specific groups endpoint (default domain)
            # Fetch all groups with pagination support
            groups: List[Dict[str, Any]] = []
            cursor = None
            page_size = 1000  # Max page size per NSX API
            
            while True:
                groups_url = f"{self.base_url}/policy/api/v1/infra/domains/default/groups"
                params = {"page_size": page_size}
                if cursor:
                    params["cursor"] = cursor
                
                response = self._nsx_get(groups_url, params=params, timeout=15)
                response.raise_for_status()
                groups_data = response.json()
                
                page_groups = groups_data.get("results", [])
                if not page_groups:
                    break
                
                for group in page_groups:
                    group_id = group.get("id", "")
                    group_path = group.get("path", "")
                    if not group_id:
                        continue

                    # 1) Get group definition (expressions, etc.)
                    detail_url = (
                        f"{self.base_url}/policy/api/v1/infra/domains/default/groups/{group_id}"
                    )
                    try:
                        detail_resp = self._nsx_get(detail_url, timeout=15)
                        if detail_resp.status_code == 404:
                            logger.debug(
                                "Skipping group %s during catalog refresh: HTTP 404",
                                group_id,
                            )
                            continue
                        detail_resp.raise_for_status()
                        detail = detail_resp.json()
                        detail["path"] = group_path  # ensure path is present
                    except requests.exceptions.RequestException as e:
                        logger.warning(f"Failed to get group detail for {group_id}: {e}")
                        continue

                    # 2) Get IP members using the dedicated NSX API with pagination:
                    #    /policy/api/v1/infra/domains/{domain-id}/groups/{group-id}/members/ip-addresses
                    members_url = (
                        f"{self.base_url}/policy/api/v1/infra/domains/default/"
                        f"groups/{group_id}/members/ip-addresses"
                    )
                    ip_members: List[Any] = []
                    members_cursor = None
                    
                    try:
                        while True:
                            members_params = {"page_size": 1000}
                            if members_cursor:
                                members_params["cursor"] = members_cursor
                            
                            members_resp = self._nsx_get(members_url, params=members_params, timeout=15)
                            members_resp.raise_for_status()
                            members_data = members_resp.json()
                            
                            page_members = members_data.get("results", [])
                            if not page_members:
                                break
                            
                            ip_members.extend(page_members)
                            
                            # Check for next page
                            members_cursor = members_data.get("cursor")
                            if not members_cursor:
                                break
                            
                            # Small delay between member pages
                            time.sleep(0.02)
                        
                        detail["ip_members"] = ip_members
                    except requests.exceptions.RequestException as e:
                        logger.warning(f"Failed to get IP members for group {group_id}: {e}")
                        detail["ip_members"] = []

                    # Calculate and store member count for selection logic
                    detail["member_count"] = self._calculate_member_count(detail)
                    groups.append(detail)

                    # Soft rate limit within a refresh: sleep a bit between
                    # requests so we don't exceed NSX per-client RPS.
                    time.sleep(0.05)  # ~20 requests per second max
                
                # Check for next page of groups
                cursor = groups_data.get("cursor")
                if not cursor:
                    break
                
                # Small delay between group list pages
                time.sleep(0.05)

            self._groups = groups
            self._groups_last_refresh = now
            self._last_refresh_attempt = now

            self._rebuild_group_maps()
            
            logger.info(f"Refreshed NSX groups cache, loaded {len(groups)} groups")
            # Write full group/membership details to log file for debugging/inspection
            logger.debug("NSX groups detail: %r", self._groups)

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to refresh NSX groups from NSX-T: {e}")
            # don't blow up; leave existing groups in place if any

    def _rebuild_group_maps(self) -> None:
        """Populate _groups_by_path / _groups_by_id from self._groups."""
        self._groups_by_path = {}
        self._groups_by_id = {}
        for g in self._groups:
            path = g.get("path", "")
            gid = g.get("id", "")
            if path:
                self._groups_by_path[path] = g
            if gid:
                self._groups_by_id[gid] = g

    def _list_groups_paginated(
        self,
        *,
        member_types: Optional[str] = None,
        page_size: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        List all domain groups via the lightweight list API (no per-group detail/members).
        """
        groups: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        while True:
            groups_url = f"{self.base_url}/policy/api/v1/infra/domains/default/groups"
            params: Dict[str, Any] = {"page_size": page_size}
            if cursor:
                params["cursor"] = cursor
            if member_types:
                params["member_types"] = member_types

            response = self._nsx_get(groups_url, params=params, timeout=60)
            response.raise_for_status()
            groups_data = response.json()

            page_groups = groups_data.get("results", [])
            if not page_groups:
                break

            groups.extend(page_groups)

            cursor = groups_data.get("cursor")
            if not cursor:
                break

            time.sleep(0.05)

        return groups

    def _reload_catalog_from_group_list_only(self) -> None:
        """
        Replace the in-memory group catalog using only the paginated list endpoint.

        Used for explicit UI refresh so we do not issue two HTTP calls per group
        (read group + list all IP members). IP members are loaded lazily during
        membership checks.
        """
        now = time.time()
        groups: List[Dict[str, Any]] = []
        cfg_filter = self.config.group_list_member_types

        def _load_unfiltered() -> List[Dict[str, Any]]:
            return self._list_groups_paginated(member_types=None)

        try:
            if cfg_filter == "off":
                groups = _load_unfiltered()
            elif cfg_filter:
                try:
                    groups = self._list_groups_paginated(member_types=cfg_filter)
                except requests.exceptions.HTTPError as e:
                    if e.response is not None and e.response.status_code == 400:
                        logger.info(
                            "NSX group list rejected member_types=%r (400), retrying without filter",
                            cfg_filter,
                        )
                        groups = _load_unfiltered()
                    else:
                        raise
            else:
                default_filter = "IPAddress,NestedGroup"
                try:
                    groups = self._list_groups_paginated(member_types=default_filter)
                except requests.exceptions.HTTPError as e:
                    if e.response is not None and e.response.status_code == 400:
                        logger.info(
                            "NSX group list rejected default member_types=%r (400), listing all groups",
                            default_filter,
                        )
                        groups = _load_unfiltered()
                    else:
                        raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to list NSX groups from NSX-T: {e}")
            return

        self._groups = groups
        self._rebuild_group_maps()
        self._groups_last_refresh = now
        self._last_refresh_attempt = now
        self.clear_cache()
        logger.info("Reloaded NSX group catalog from list API only (%s groups)", len(groups))

    def _fetch_ip_members_pages(self, group_id: str) -> List[Any]:
        """Return all IP member entries for a group from members/ip-addresses (paginated)."""
        ip_members: List[Any] = []
        members_url = (
            f"{self.base_url}/policy/api/v1/infra/domains/default/"
            f"groups/{group_id}/members/ip-addresses"
        )
        members_cursor: Optional[str] = None

        while True:
            members_params: Dict[str, Any] = {"page_size": 1000}
            if members_cursor:
                members_params["cursor"] = members_cursor

            members_resp = self._nsx_get(members_url, params=members_params, timeout=30)
            members_resp.raise_for_status()
            members_data = members_resp.json()

            page_members = members_data.get("results", [])
            if not page_members:
                break

            ip_members.extend(page_members)

            members_cursor = members_data.get("cursor")
            if not members_cursor:
                break

            time.sleep(0.02)

        return ip_members

    def _group_ip_matches_members_paginated_scan(self, group_id: str, ip: str) -> bool:
        """
        True if ip appears in members/ip-addresses for this group.
        Stops at the first matching page element (does not load the full member list).
        """
        members_url = (
            f"{self.base_url}/policy/api/v1/infra/domains/default/"
            f"groups/{group_id}/members/ip-addresses"
        )
        members_cursor: Optional[str] = None
        try:
            while True:
                members_params: Dict[str, Any] = {"page_size": 1000}
                if members_cursor:
                    members_params["cursor"] = members_cursor

                members_resp = self._nsx_get(members_url, params=members_params, timeout=30)
                members_resp.raise_for_status()
                members_data = members_resp.json()

                page_members = members_data.get("results", [])
                if not page_members:
                    return False

                for elem in page_members:
                    if self._ip_matches_member_element(ip, elem):
                        return True

                members_cursor = members_data.get("cursor")
                if not members_cursor:
                    return False

                if threading.current_thread() is threading.main_thread():
                    time.sleep(0.02)
        except requests.exceptions.RequestException as e:
            logger.warning("IP members scan failed for group %s: %s", group_id, e)
            return False

    def _split_catalog_into_chunks(self, seq: List[Dict[str, Any]], n_chunks: int) -> List[List[Dict[str, Any]]]:
        """Split seq into up to n_chunks non-empty sublists of nearly equal size."""
        if not seq:
            return []
        n_chunks = max(1, min(n_chunks, len(seq)))
        k, m = divmod(len(seq), n_chunks)
        chunks: List[List[Dict[str, Any]]] = []
        start = 0
        for i in range(n_chunks):
            end = start + k + (1 if i < m else 0)
            part = seq[start:end]
            if part:
                chunks.append(part)
            start = end
        return chunks

    def _match_groups_chunk(
        self,
        ip_address: str,
        chunk: List[Dict[str, Any]],
        allow_nested: bool = True,
    ) -> List[Dict[str, Any]]:
        return [g for g in chunk if self._ip_matches_group(ip_address, g, allow_nested=allow_nested)]

    def _collect_groups_matching_ip(
        self,
        ip_address: str,
        *,
        allow_nested: bool = True,
    ) -> List[Dict[str, Any]]:
        """All group dicts in the current catalog that contain ip_address."""
        all_g = self._groups
        workers = max(1, int(self.config.ip_group_lookup_parallelism))
        if workers <= 1 or len(all_g) < 64:
            return [g for g in all_g if self._ip_matches_group(ip_address, g, allow_nested=allow_nested)]

        chunks = self._split_catalog_into_chunks(all_g, workers)
        if len(chunks) <= 1:
            return [g for g in all_g if self._ip_matches_group(ip_address, g, allow_nested=allow_nested)]

        out: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=len(chunks)) as ex:
            futures = [
                ex.submit(self._match_groups_chunk, ip_address, ch, allow_nested)
                for ch in chunks
            ]
            for fut in as_completed(futures):
                out.extend(fut.result())
        return out

    def _ensure_ip_members_loaded(self, group_detail: dict) -> None:
        """Attach ip_members to group_detail if not already present (lazy fetch)."""
        if "ip_members" in group_detail:
            return
        gid = group_detail.get("id", "")
        if not gid:
            group_detail["ip_members"] = []
            return
        try:
            group_detail["ip_members"] = self._fetch_ip_members_pages(gid)
        except requests.exceptions.RequestException as e:
            logger.warning("Failed to get IP members for group %s: %s", gid, e)
            group_detail["ip_members"] = []

    def _group_id_from_path_or_id(self, path_or_id: str) -> str:
        s = (path_or_id or "").strip()
        if "/" in s:
            return s.rstrip("/").split("/")[-1]
        return s

    def _fetch_group_detail_by_id(self, group_id: str) -> Optional[Dict[str, Any]]:
        if not group_id:
            return None
        enc = quote(str(group_id).strip(), safe="")
        detail_url = f"{self.base_url}/policy/api/v1/infra/domains/default/groups/{enc}"
        try:
            detail_resp = self._nsx_get(detail_url, timeout=30)
            if detail_resp.status_code == 200:
                return detail_resp.json()
            if detail_resp.status_code == 404:
                logger.debug(
                    "Failed to read group %s: HTTP 404", group_id
                )
                return None
            logger.warning(
                "Failed to read group %s: HTTP %s", group_id, detail_resp.status_code
            )
            return None
        except requests.exceptions.RequestException as e:
            logger.warning("Failed to read group %s: %s", group_id, e)
            return None

    def _group_list_row_matches_lookup_label(self, g: Dict[str, Any], key: str) -> bool:
        """True if list/summary row g matches user-supplied label (id, display_name, path tail, extract name)."""
        if not key:
            return False
        gid = str(g.get("id", "") or "")
        if gid == key:
            return True
        disp = str(g.get("display_name", "") or "").strip()
        if disp == key:
            return True
        path = str(g.get("path", "") or "")
        if path:
            tail = path.rstrip("/").split("/")[-1]
            if tail == key:
                return True
        return self._extract_group_name(g) == key

    def _find_group_summary_by_label_in_domain_list(self, label: str) -> Optional[Dict[str, Any]]:
        """
        Paginate GET .../groups (unfiltered) and return the first row whose id/display_name/path
        matches ``label``. Used when GET .../groups/{label} returns 404 (display_name != policy id).
        """
        key = (label or "").strip()
        if not key:
            return None

        groups_url = f"{self.base_url}/policy/api/v1/infra/domains/default/groups"
        cursor: Optional[str] = None
        page_size = 1000

        try:
            while True:
                params: Dict[str, Any] = {"page_size": page_size}
                if cursor:
                    params["cursor"] = cursor

                response = self._nsx_get(groups_url, params=params, timeout=60)
                response.raise_for_status()
                data = response.json()
                for g in data.get("results") or []:
                    if isinstance(g, dict) and self._group_list_row_matches_lookup_label(g, key):
                        return g

                cursor = data.get("cursor")
                if not cursor:
                    break
                time.sleep(0.05)
        except requests.exceptions.RequestException as e:
            logger.warning("Group list scan for label %r failed: %s", key, e)
            return None

        return None

    def _resolve_group_detail_for_lookup_name(self, raw_name: str) -> Optional[Dict[str, Any]]:
        """
        Resolve a user-supplied group label to a detail dict (from cache or GET by id).
        Accepts NSX policy id, display_name, path tail, or full path.
        """
        key = (raw_name or "").strip()
        if not key:
            return None

        hit = self._groups_by_id.get(key) or self._groups_by_path.get(key)
        if hit is not None:
            return hit

        for path, g in self._groups_by_path.items():
            if path.rstrip("/").split("/")[-1] == key:
                return g

        for g in self._groups:
            gid = g.get("id", "")
            if gid == key or self._extract_group_name(g) == key:
                if gid:
                    full = self._fetch_group_detail_by_id(gid)
                    if full:
                        if not full.get("path") and g.get("path"):
                            full["path"] = g.get("path", "")
                        return self._register_group_detail(full)
                return g

        enc = quote(str(key).strip(), safe="")
        detail_url = f"{self.base_url}/policy/api/v1/infra/domains/default/groups/{enc}"
        try:
            detail_resp = self._nsx_get(detail_url, timeout=30)
            if detail_resp.status_code == 200:
                return self._register_group_detail(detail_resp.json())
            not_found = detail_resp.status_code == 404
            if not not_found:
                logger.warning(
                    "Failed to read group %s: HTTP %s", key, detail_resp.status_code
                )
                return None
        except requests.exceptions.RequestException as e:
            logger.warning("Failed to read group %s: %s", key, e)
            return None

        summary = self._find_group_summary_by_label_in_domain_list(key)
        if not summary:
            return None
        real_id = str(summary.get("id", "") or "").strip()
        if not real_id or real_id == key:
            return summary
        full = self._fetch_group_detail_by_id(real_id)
        if full:
            if not full.get("path") and summary.get("path"):
                full["path"] = summary.get("path", "")
            return self._register_group_detail(full)
        return summary

    def _lookup_all_ip_groups_for_named_candidates(
        self,
        ip_address: str,
        names: List[str],
        *,
        allow_nested: bool = True,
    ) -> List[str]:
        """Membership check only for the given group names/ids (no full domain list)."""
        ordered_unique: List[str] = []
        seen = set()
        for n in names:
            s = (n or "").strip()
            if s and s not in seen:
                seen.add(s)
                ordered_unique.append(s)

        by_id: Dict[str, Dict[str, Any]] = {}
        for raw in ordered_unique:
            detail = self._resolve_group_detail_for_lookup_name(raw)
            if detail and detail.get("id"):
                by_id.setdefault(str(detail["id"]), detail)

        matched_details: List[Dict[str, Any]] = []
        for detail in by_id.values():
            if self._ip_matches_group(ip_address, detail, allow_nested=allow_nested):
                matched_details.append(detail)

        matching: List[Tuple[str, int]] = []
        for group_detail in matched_details:
            name = self._extract_group_name(group_detail)
            if not name:
                continue
            group_detail["member_count"] = self._calculate_member_count(group_detail)
            if int(group_detail["member_count"]) >= 999999:
                self._ensure_ip_members_loaded(group_detail)
                group_detail["member_count"] = self._calculate_member_count(group_detail)
            matching.append((name, int(group_detail["member_count"])))

        if not matching:
            return []

        best_count_by_name: Dict[str, int] = {}
        for name, count in matching:
            previous = best_count_by_name.get(name)
            if previous is None or count < previous:
                best_count_by_name[name] = count

        return [name for name, _count in sorted(best_count_by_name.items(), key=lambda nc: (nc[1], nc[0]))]

    def _register_group_detail(self, detail: Dict[str, Any]) -> Dict[str, Any]:
        """Merge a fetched group into the catalog and maps; return the canonical dict."""
        gid = detail.get("id", "")
        if not gid:
            return detail

        with self._catalog_lock:
            existing = self._groups_by_id.get(gid)
            if existing is not None:
                existing.update(detail)
                return existing

            self._groups.append(detail)
            path = detail.get("path", "")
            if path:
                self._groups_by_path[path] = detail
            self._groups_by_id[gid] = detail
            return detail

    def _resolve_group_path_or_id(
        self,
        path_or_id: str,
        *,
        membership_lookup: MembershipLookup = "live",
    ) -> Optional[Dict[str, Any]]:
        """Return group detail from catalog; live mode may fetch from NSX on cache miss."""
        if not path_or_id:
            return None
        nested = self._groups_by_path.get(path_or_id) or self._groups_by_id.get(path_or_id)
        if nested is not None:
            return nested

        gid = self._group_id_from_path_or_id(path_or_id)
        if gid:
            nested = self._groups_by_id.get(gid)
            if nested is not None:
                return nested
            for path, g in self._groups_by_path.items():
                if path.rstrip("/").split("/")[-1] == gid:
                    return g

        if membership_lookup == "cache":
            return None

        detail = self._fetch_group_detail_by_id(gid)
        if not detail:
            return None
        return self._register_group_detail(detail)
    
    def lookup_ip_groups(self, ip_address: str) -> Optional[List[str]]:
        """
        Lookup which NSX groups contain the given IP address.
        Returns only the group(s) with the least effective members.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            List containing the group name(s) with least members, or empty list.
        """
        # Check per-IP cache first
        cached = self._get_from_cache(ip_address)
        if cached is not None:
            return cached
        
        # Ensure we have a fresh in-memory group list
        self._refresh_groups_if_needed()

        matching_groups: List[Tuple[str, int]] = []  # (name, member_count)
        for group_detail in self._groups:
            if self._ip_matches_group(ip_address, group_detail):
                # Extract just the group name (not full path)
                name = self._extract_group_name(group_detail)
                if name:
                    member_count = group_detail.get("member_count", 999999)
                    matching_groups.append((name, member_count))

        if not matching_groups:
            self._store_in_cache(ip_address, [])
            return []
        
        # Select group(s) with the least members
        min_count = min(count for _, count in matching_groups)
        selected = sorted({name for name, count in matching_groups if count == min_count})
        
        # Store in cache (even if empty list) so repeated lookups are cheap
        self._store_in_cache(ip_address, selected)
        return selected

    def lookup_all_ip_groups(
        self,
        ip_address: str,
        refresh: bool = False,
        only_group_names: Optional[List[str]] = None,
        *,
        direct_membership_only: bool = False,
    ) -> List[str]:
        """
        Lookup all NSX groups that contain the given IP address.
        Includes matches through nested groups by default; returns a stable order.

        Args:
            ip_address: IP address to lookup
            refresh: If True, reload group metadata from NSX using only the
                paginated list endpoint, then resolve membership (IP members are
                fetched lazily per group as needed). Avoids downloading every
                group's full member list up front.
            only_group_names: If non-empty, skip full catalog load and only evaluate
                these groups (by id, display_name, or path tail). Intended for UI
                refresh with explicit candidate groups.
            direct_membership_only: If True, do not recurse into nested groups;
                only direct criteria on each group (expression IPs, static fields,
                members/ip-addresses). Used for UI \"refresh groups\".

        Returns:
            Sorted list of unique group names (smallest groups first).
        """
        allow_nested = not direct_membership_only

        filtered = [x.strip() for x in (only_group_names or []) if x and str(x).strip()]
        if filtered:
            cache_key = self._get_cache_key(ip_address)
            self._ip_cache.pop(cache_key, None)
            self._cache_timestamps.pop(cache_key, None)
            return self._lookup_all_ip_groups_for_named_candidates(
                ip_address, filtered, allow_nested=allow_nested
            )

        if refresh:
            self._reload_catalog_from_group_list_only()

        matched_details = self._collect_groups_matching_ip(ip_address, allow_nested=allow_nested)

        matching: List[Tuple[str, int]] = []
        for group_detail in matched_details:
            name = self._extract_group_name(group_detail)
            if not name:
                continue
            group_detail["member_count"] = self._calculate_member_count(group_detail)
            if int(group_detail["member_count"]) >= 999999:
                self._ensure_ip_members_loaded(group_detail)
                group_detail["member_count"] = self._calculate_member_count(group_detail)
            member_count = int(group_detail["member_count"])
            matching.append((name, member_count))

        if not matching:
            return []

        best_count_by_name: Dict[str, int] = {}
        for name, count in matching:
            previous = best_count_by_name.get(name)
            if previous is None or count < previous:
                best_count_by_name[name] = count

        return [name for name, _count in sorted(best_count_by_name.items(), key=lambda nc: (nc[1], nc[0]))]
    
    def _calculate_member_count(self, group_detail: dict) -> int:
        """
        Calculate the total number of individual IP addresses in a group.
        Counts individual IPs, not just member entries (e.g., /24 = 256 IPs).
        
        Args:
            group_detail: Group detail dictionary from NSX-T API
            
        Returns:
            Total count of individual IP addresses
        """
        try:
            from ipaddress import ip_address, ip_network
        except ImportError:
            # Fallback to simple count if ipaddress not available
            return len(group_detail.get("ip_members", []))
        
        total_ips = 0
        
        # Count explicit IP members from members/ip-addresses API
        ip_members = group_detail.get("ip_members", [])
        if isinstance(ip_members, list):
            for member in ip_members:
                total_ips += self._count_ips_in_member(member)
        
        # If no explicit members, count from other fields
        if total_ips == 0:
            # Count from ip_addresses list (each is 1 IP)
            ip_addresses = group_detail.get("ip_addresses", [])
            if isinstance(ip_addresses, list):
                total_ips += len(ip_addresses)
            
            # Count from ip_ranges list (calculate IPs in each range)
            ip_ranges = group_detail.get("ip_ranges", [])
            if isinstance(ip_ranges, list):
                for ip_range in ip_ranges:
                    if isinstance(ip_range, str):
                        total_ips += self._count_ips_in_member(ip_range)
            
            # Count from expressions
            expression = group_detail.get("expression", [])
            if expression:
                expressions = expression if isinstance(expression, list) else [expression]
                for expr in expressions:
                    if isinstance(expr, dict):
                        expr_ips = expr.get("ip_addresses", [])
                        if isinstance(expr_ips, list):
                            total_ips += len(expr_ips)
        
        # If still 0, default to a high number (groups with no direct members
        # might be nested-only, so we prefer groups with explicit members)
        return total_ips if total_ips > 0 else 999999
    
    def _count_ips_in_member(self, member: Any) -> int:
        """
        Count the number of individual IP addresses in a member element.
        
        Args:
            member: Member element (string or dict) - can be CIDR, IP range, or single IP
            
        Returns:
            Number of individual IPs
        """
        try:
            from ipaddress import ip_address, ip_network
        except ImportError:
            return 1  # Fallback: assume 1 IP
        
        # Extract value from dict or use string directly
        if isinstance(member, dict):
            value = member.get("ip_address") or member.get("ip_addresses") or member.get("value")
        else:
            value = str(member)
        
        if not value:
            return 0
        
        value = str(value).strip()
        
        # IP range: "start-end"
        if "-" in value and "/" not in value:
            try:
                start_s, end_s = value.split("-", 1)
                start_ip = ip_address(start_s.strip())
                end_ip = ip_address(end_s.strip())
                # Count IPs in range (inclusive)
                return int(end_ip) - int(start_ip) + 1
            except (ValueError, AttributeError):
                return 1
        
        # CIDR subnet: "10.0.0.0/24"
        if "/" in value:
            try:
                network = ip_network(value, strict=False)
                return network.num_addresses
            except (ValueError, AttributeError):
                return 1
        
        # Single IP
        try:
            ip_address(value)
            return 1
        except ValueError:
            return 1
    
    def _extract_group_name(self, group_detail: dict) -> str:
        """
        Extract just the group name from a group detail dict.
        Prefers display_name, then extracts name from path, then falls back to id.
        
        Args:
            group_detail: Group detail dictionary from NSX-T API
            
        Returns:
            Group name string, or empty string if none found
        """
        # Prefer display_name if available
        display_name = group_detail.get("display_name", "")
        if display_name:
            return display_name
        
        # Extract name from path (last component after final /)
        path = group_detail.get("path", "")
        if path:
            # Path format: /infra/domains/default/groups/group-name
            # Extract the last component
            parts = path.strip("/").split("/")
            if parts:
                name = parts[-1]
                if name:
                    return name
        
        # Fall back to id
        group_id = group_detail.get("id", "")
        if group_id:
            return group_id
        
        return ""
    
    def _ip_matches_group(
        self,
        ip: str,
        group_detail: dict,
        visited: Optional[set] = None,
        *,
        allow_nested: bool = True,
        membership_lookup: MembershipLookup = "live",
    ) -> bool:
        """
        Check if an IP address matches a group's membership criteria.
        Optionally recurses into nested groups (NSX group expressions).
        
        Args:
            ip: IP address to check
            group_detail: Group detail dictionary from NSX-T API
            visited: Set of group paths/IDs already visited (to prevent infinite loops)
            allow_nested: If False, skip nested-group recursion (direct membership only).
            membership_lookup: "cache" uses preloaded ip_members only (syslog ingest);
                "live" may query NSX members/ip-addresses per group (UI).
            
        Returns:
            True if IP matches group membership
        """
        if visited is None:
            visited = set()
        
        # Prevent infinite loops from circular group references
        group_id = group_detail.get("id", "")
        group_path = group_detail.get("path", "")
        visit_key = group_id or group_path
        if visit_key and visit_key in visited:
            return False
        if visit_key:
            visited.add(visit_key)

        # Check expression criteria first (list API usually includes expression;
        # avoids a members/ip-addresses round-trip when membership is declared here)
        expression = group_detail.get('expression', [])
        if expression:
            expressions = expression if isinstance(expression, list) else [expression]
            for expr in expressions:
                if isinstance(expr, dict):
                    if self._ip_matches_expression(ip, expr):
                        return True
                    if allow_nested and self._expression_has_nested_groups(expr):
                        nested_groups = self._extract_nested_groups_from_expression(
                            expr, membership_lookup=membership_lookup
                        )
                        for nested_group in nested_groups:
                            if self._ip_matches_group(
                                ip,
                                nested_group,
                                visited,
                                allow_nested=allow_nested,
                                membership_lookup=membership_lookup,
                            ):
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

        if membership_lookup == "cache":
            ip_members = group_detail.get("ip_members")
            if isinstance(ip_members, list) and ip_members:
                for elem in ip_members:
                    if self._ip_matches_member_element(ip, elem):
                        return True
            return False

        if self._group_has_only_mac_expression_criteria(group_detail):
            return False

        gid = group_detail.get("id", "")
        if gid and self._group_ip_matches_members_paginated_scan(gid, ip):
            return True

        return False

    def _group_has_only_mac_expression_criteria(self, group_detail: dict) -> bool:
        """If all criteria are MAC-only, skip members/ip-addresses for IPv4 lookups."""
        expression = group_detail.get("expression")
        if not expression:
            return False
        expressions = expression if isinstance(expression, list) else [expression]
        if not expressions:
            return False
        for expr in expressions:
            if not isinstance(expr, dict):
                return False
            if expr.get("resource_type") != "MACAddressExpression":
                return False
        return True

    def _expression_has_nested_groups(self, expression: dict) -> bool:
        """Check if an expression contains nested group references."""
        expr_type = expression.get('resource_type', '')
        # Common NSX-T expression types that reference groups
        if expr_type in ('GroupExpression', 'NestedExpression', 'Condition'):
            return True
        # Check if expression has member_groups or similar fields
        if 'member_groups' in expression or 'groups' in expression or 'group_paths' in expression:
            return True
        return False
    
    def _extract_nested_groups_from_expression(
        self,
        expression: dict,
        *,
        membership_lookup: MembershipLookup = "live",
    ) -> List[Dict[str, Any]]:
        """
        Extract nested group references from an expression and return their group details.
        
        Returns:
            List of group detail dictionaries for nested groups
        """
        nested_groups = []
        
        # Check various fields that might contain group references
        group_paths = expression.get('group_paths', [])
        if not group_paths:
            group_paths = expression.get('member_groups', [])
        if not group_paths:
            group_paths = expression.get('groups', [])
        if not group_paths:
            group_paths = expression.get('paths', [])
        if not group_paths:
            # Sometimes it's a single path/id
            path = expression.get('path') or expression.get('group_path') or expression.get('id')
            if path:
                group_paths = [path]
        
        for path_or_id in group_paths:
            nested = self._resolve_group_path_or_id(
                path_or_id, membership_lookup=membership_lookup
            )
            if nested:
                nested_groups.append(nested)

        return nested_groups

    def _ip_matches_member_element(self, ip: str, element: Any) -> bool:
        """
        Check if an IP matches a single member element from the
        members/ip-addresses API. Elements may be strings or objects
        depending on NSX version (CIDR, single IP, or IP range).
        """
        try:
            from ipaddress import ip_address, ip_network
        except ImportError:
            return False

        # Element can be a plain string (e.g. "192.168.0.0/24" or "1.2.3.4")
        # or a range like "1.2.3.4-1.2.3.100", or a dict with such fields.
        if isinstance(element, dict):
            value = element.get("ip_address") or element.get("ip_addresses") or element.get("value")
        else:
            value = str(element)

        if not value:
            return False

        value = value.strip()

        # Range: "start-end"
        if "-" in value and "/" not in value:
            start_s, end_s = value.split("-", 1)
            try:
                ip_obj = ip_address(ip)
                start_ip = ip_address(start_s.strip())
                end_ip = ip_address(end_s.strip())
                return start_ip <= ip_obj <= end_ip
            except ValueError:
                return False

        # CIDR or single IP
        try:
            # If it's CIDR, this works; if it's a host IP, ip_network with /32
            if "/" in value:
                network = ip_network(value, strict=False)
                return ip_address(ip) in network
            else:
                return ip_address(ip) == ip_address(value)
        except ValueError:
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

    # -------- NSX-T policy and rule helpers for UI --------

    def list_application_policies(self) -> List[Dict[str, Any]]:
        """
        List security policies in the default domain that belong to the
        Application section/category.

        Returns a list of small dicts: {id, name, category}.
        """
        policies: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        page_size = 1000

        try:
            while True:
                url = f"{self.base_url}/policy/api/v1/infra/domains/default/security-policies"
                params: Dict[str, Any] = {"page_size": page_size}
                if cursor:
                    params["cursor"] = cursor

                resp = self._nsx_get(url, params=params, timeout=15)
                resp.raise_for_status()
                data = resp.json()
                results = data.get("results", []) or []
                for p in results:
                    category = p.get("category", "")
                    if category.lower() != "application":
                        continue
                    pid = p.get("id") or ""
                    if not pid:
                        continue
                    name = p.get("display_name") or pid
                    policies.append(
                        {
                            "id": pid,
                            "name": name,
                            "category": category,
                        }
                    )

                cursor = data.get("cursor")
                if not cursor:
                    break

                time.sleep(0.05)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to list NSX-T policies: {e}")

        return policies

    def list_services(self) -> List[Dict[str, Any]]:
        """
        List L4 services defined in NSX-T Policy.

        Returns a list of dicts:
            {id, name, display, protocol, ports: [\"443\", ...],
             service_entries: [{l4_protocol, destination_ports: [...]}, ...]}
        Per-entry data preserves correct L4 when a service has multiple entries (e.g. TCP and UDP).
        """
        services: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        page_size = 1000

        try:
            while True:
                url = f"{self.base_url}/policy/api/v1/infra/services"
                params: Dict[str, Any] = {"page_size": page_size}
                if cursor:
                    params["cursor"] = cursor

                resp = self._nsx_get(url, params=params, timeout=15)
                resp.raise_for_status()
                data = resp.json()
                results = data.get("results", []) or []

                for svc in results:
                    sid = svc.get("id") or ""
                    if not sid:
                        continue
                    display_name = svc.get("display_name") or sid
                    service_entries = svc.get("service_entries") or []

                    ports_set = set()
                    protocol = None
                    serialized_entries: List[Dict[str, Any]] = []
                    for entry in service_entries:
                        entry_ports = entry.get("destination_ports") or []
                        for p in entry_ports:
                            ports_set.add(str(p))
                        proto = entry.get("l4_protocol")
                        if proto and not protocol:
                            protocol = proto
                        serialized_entries.append(
                            {
                                "l4_protocol": proto,
                                "destination_ports": [str(p) for p in entry_ports],
                            }
                        )

                    services.append(
                        {
                            "id": sid,
                            "name": display_name,
                            "display": display_name,
                            "protocol": protocol,
                            "ports": sorted(ports_set),
                            "service_entries": serialized_entries,
                        }
                    )

                cursor = data.get("cursor")
                if not cursor:
                    break

                time.sleep(0.05)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to list NSX-T services: {e}")

        return services

    def _group_name_to_path(self, name: str) -> Optional[str]:
        """
        Resolve a human-friendly group name (as shown in the UI) back to the
        NSX-T Policy group path using the cached groups.
        """
        if not name:
            return None

        self._refresh_groups_if_needed()
        for detail in self._groups:
            if self._extract_group_name(detail) == name:
                path = detail.get("path") or ""
                if path:
                    return path
        return None

    def _sanitize_id(self, value: str) -> str:
        """
        Turn an arbitrary name into a safe NSX-T Policy object id.
        """
        if not value:
            return "rule-auto"
        v = value.strip().lower()
        v = re.sub(r"[^a-z0-9]+", "-", v)
        v = v.strip("-")
        return v or "rule-auto"

    def create_firewall_rule(
        self,
        *,
        policy_id: str,
        rule_name: str,
        direction: str,
        source_group_names: List[str],
        dest_group_names: List[str],
        applied_to_group_names: List[str],
        service_id: str,
        ip_protocol: Optional[str] = None,
        description: Optional[str] = None,
        label: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a distributed firewall rule under the given security policy.

        The rule is always created disabled and with logging enabled.
        """
        if not policy_id:
            raise ValueError("policy_id is required")
        if not service_id:
            raise ValueError("service_id is required")

        src_paths = [
            self._group_name_to_path(n) for n in source_group_names if n
        ]
        dst_paths = [
            self._group_name_to_path(n) for n in dest_group_names if n
        ]
        applied_paths = [
            self._group_name_to_path(n) for n in applied_to_group_names if n
        ]

        if not all(src_paths):
            raise ValueError("Failed to resolve all source groups to NSX paths")
        if not all(dst_paths):
            raise ValueError("Failed to resolve all destination groups to NSX paths")
        if not all(applied_paths):
            raise ValueError("Failed to resolve all applied-to groups to NSX paths")

        service_path = f"/infra/services/{service_id}"

        rule_id = self._sanitize_id(rule_name)
        url = (
            f"{self.base_url}/policy/api/v1/infra/domains/default/"
            f"security-policies/{policy_id}/rules/{rule_id}"
        )

        payload: Dict[str, Any] = {
            "display_name": rule_name,
            "disabled": True,  # create deactivated
            "logged": True,  # enable packet logging
            "source_groups": src_paths,
            "destination_groups": dst_paths,
            "services": [service_path],
            "direction": direction,
            "scope": applied_paths,
            "action": "ALLOW",
        }
        if ip_protocol:
            payload["ip_protocol"] = ip_protocol
        # Long-form description for config / UI
        # NSX-T limits:
        # - description: max 1024 chars
        # - notes: max 2048 chars
        if description:
            payload["description"] = description[:1024]
            payload["notes"] = description[:2048]

        # `label` from the caller is the log/CLI tag (policyName_ruleName).
        # The structured tags[] entry with scope "label" is a fixed tool marker.
        if label:
            payload["tag"] = label  # printed in CLI and packet logs

        tags: List[Dict[str, Any]] = [
            {"scope": "label", "tag": CREATED_BY_TOOL_LABEL_TAG},
        ]
        payload["tags"] = tags

        try:
            resp = self.session.put(url, json=payload, timeout=20)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create NSX-T firewall rule: {e}")
            raise

