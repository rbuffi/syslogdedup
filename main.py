#!/usr/bin/env python3
"""Main syslog server for receiving, deduplicating, and forwarding firewall logs."""
import logging
import signal
import socket
import struct
import sys
import threading
from typing import List, Optional, Tuple
from config import load_config, Config
from parser import LogParser
from deduplicator import Deduplicator
from nsxt_client import NSXTClient
from forwarder import SyslogForwarder
from influx_client import InfluxClient
from postgres_client import PostgresClient


# Configure logging (console)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

# Dedicated file logger for NSX lookup failures.
# This file should contain only the raw syslog line and the reason why group
# resolution failed, one entry per failed item.
_nsx_file_handler = logging.FileHandler("nsx_groups.log")
_nsx_file_handler.setLevel(logging.WARNING)
_nsx_file_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)
nsx_failure_logger = logging.getLogger("nsx_group_failures")
nsx_failure_logger.setLevel(logging.WARNING)
nsx_failure_logger.addHandler(_nsx_file_handler)

logger = logging.getLogger(__name__)


class SyslogServer:
    """UDP syslog server for processing firewall logs."""
    
    def __init__(self, config: Config):
        """
        Initialize the syslog server.
        
        Args:
            config: Config object with all configuration
        """
        self.config = config
        self.parser = LogParser()
        self.deduplicator = Deduplicator()
        self.nsxt_client = NSXTClient(config.nsxt, ingest_mode=True)
        self.nsxt_client.refresh_ingest_catalog(force=True)
        self._ingest_catalog_refresh_stop = threading.Event()
        self._ingest_catalog_refresh_thread = threading.Thread(
            target=self._ingest_catalog_refresh_loop,
            name="nsx-ingest-catalog-refresh",
            daemon=True,
        )
        self._ingest_catalog_refresh_thread.start()
        self.forwarder: Optional[SyslogForwarder] = None
        if config.syslog.forward_enabled:
            self.forwarder = SyslogForwarder(config.syslog)
        else:
            logger.info("Syslog forwarding is disabled (SYSLOG_FORWARD_ENABLED=false)")
        self.influx_client = InfluxClient(config.influx)
        self.pg_client = PostgresClient(config.postgres)
        self.socket = None
        self.running = False
        
        # Statistics
        self.stats = {
            'received': 0,
            'parsed': 0,
            'duplicates': 0,
            'forwarded': 0,
            'errors': 0,
            'dropped': 0,
        }
        self._last_kernel_drop_total: Optional[int] = None

    def _ingest_catalog_refresh_loop(self) -> None:
        """Refresh NSX group catalog on a fixed interval (default: cache_ttl, typically 1 hour)."""
        interval = max(1, int(self.config.nsxt.cache_ttl))
        while not self._ingest_catalog_refresh_stop.wait(interval):
            try:
                self.nsxt_client.refresh_ingest_catalog(force=True)
                logger.info("NSX ingest group catalog refreshed (scheduled)")
            except Exception as e:
                logger.warning("Scheduled NSX ingest catalog refresh failed: %s", e)

    def _setup_socket(self):
        """Create and bind UDP socket."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.config.syslog.listen_port))
            try:
                # Raise UDP receive buffer to reduce loss under bursty ingress.
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            except OSError as e:
                logger.warning(f"Failed to set UDP receive buffer size: {e}")
            try:
                actual_rcvbuf = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                logger.info(f"UDP receive buffer size (SO_RCVBUF): {actual_rcvbuf} bytes")
            except OSError as e:
                logger.warning(f"Failed to read UDP receive buffer size: {e}")
            logger.info(f"Syslog server listening on UDP port {self.config.syslog.listen_port}")
        except PermissionError:
            logger.error(f"Permission denied: Cannot bind to port {self.config.syslog.listen_port}. "
                        f"Try running with sudo or use a port >= 1024")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to setup socket: {e}")
            sys.exit(1)

    def _lookup_groups_for_ingest(self, ip_address: str) -> Tuple[Optional[List[str]], Optional[List[str]]]:
        """
        Return two group lists for an IP:
        - primary_groups: least-effective match(es) for forwarder/influx compatibility
        - all_groups: all matching groups for DB persistence
        """
        return self.nsxt_client.lookup_ingest_ip_groups(ip_address)
    
    def _process_log(self, parsed_part: str, raw_line: str):
        """
        Process a single log line through the pipeline.
        
        Args:
            parsed_part: Log line after stripping syslog header (firewall part)
            raw_line: Full raw syslog line as received
        """
        self.stats['received'] += 1
        
        # Parse the log (only the firewall part)
        parsed_log = self.parser.parse(parsed_part)
        if not parsed_log:
            # Show the complete raw line in debug to make troubleshooting easy
            logger.debug(f"Failed to parse log line (raw): {raw_line!r}")
            self.stats['errors'] += 1
            return
        
        self.stats['parsed'] += 1
        
        # Check for duplicates
        if self.deduplicator.is_duplicate(parsed_log):
            logger.debug(f"Duplicate log detected: {parsed_log.source_ip}->{parsed_log.dest_ip}")
            self.stats['duplicates'] += 1
            return
        
        # Lookup groups for source and destination IPs
        source_groups = None
        dest_groups = None
        source_groups_all = None
        dest_groups_all = None
        
        try:
            source_groups, source_groups_all = self._lookup_groups_for_ingest(parsed_log.source_ip)
        except Exception as e:
            # Log to dedicated NSX groups file with raw syslog line and reason
            nsx_failure_logger.warning(
                "NSX group lookup failed for source_ip=%s; reason=%s; raw_syslog=%r",
                parsed_log.source_ip,
                e,
                raw_line,
            )
        
        try:
            dest_groups, dest_groups_all = self._lookup_groups_for_ingest(parsed_log.dest_ip)
        except Exception as e:
            nsx_failure_logger.warning(
                "NSX group lookup failed for dest_ip=%s; reason=%s; raw_syslog=%r",
                parsed_log.dest_ip,
                e,
                raw_line,
            )
        
        # Forward the enriched log, but keep the original syslog header/line
        if self.forwarder is not None:
            if self.forwarder.forward(parsed_log, source_groups, dest_groups, raw_line=raw_line):
                self.stats['forwarded'] += 1
                logger.debug(f"Forwarded log: {parsed_log.source_ip}->{parsed_log.dest_ip}")
            else:
                self.stats['errors'] += 1
                logger.warning(f"Failed to forward log: {parsed_log.source_ip}->{parsed_log.dest_ip}")

        # Write to InfluxDB (best-effort, non-blocking on failure)
        try:
            self.influx_client.write_log(parsed_log, source_groups, dest_groups)
        except Exception as e:
            logger.debug(f"Failed to write log to InfluxDB: {e}")

        # Write to PostgreSQL (best-effort)
        try:
            self.pg_client.write_log(
                parsed_log,
                source_groups_all if source_groups_all is not None else source_groups,
                dest_groups_all if dest_groups_all is not None else dest_groups,
            )
        except Exception as e:
            logger.debug(f"Failed to write log to PostgreSQL: {e}")
    
    def _print_stats(self):
        """Print statistics."""
        logger.info(f"Stats - Received: {self.stats['received']}, "
                   f"Parsed: {self.stats['parsed']}, "
                   f"Duplicates: {self.stats['duplicates']}, "
                   f"Forwarded: {self.stats['forwarded']}, "
                   f"Errors: {self.stats['errors']}, "
                   f"Dropped: {self.stats['dropped']}")
    
    def run(self):
        """Run the syslog server main loop."""
        self._setup_socket()
        self.running = True
        
        logger.info("Syslog server started. Press Ctrl+C to stop.")
        
        try:
            while self.running:
                try:
                    # Receive UDP packet (max 65507 bytes for UDP) plus Linux
                    # ancillary data (e.g., SO_RXQ_OVFL kernel drop counter).
                    data, ancdata, _flags, addr = self.socket.recvmsg(65507, 1024)
                    raw_line = data.decode('utf-8', errors='replace')

                    # Linux-specific: if the kernel receive queue overflows, it
                    # reports a cumulative dropped-packet counter via SO_RXQ_OVFL.
                    if hasattr(socket, "SO_RXQ_OVFL"):
                        for level, ctype, cdata in ancdata:
                            if level == socket.SOL_SOCKET and ctype == socket.SO_RXQ_OVFL and len(cdata) >= 4:
                                kernel_total = struct.unpack("I", cdata[:4])[0]
                                if self._last_kernel_drop_total is not None and kernel_total >= self._last_kernel_drop_total:
                                    delta = kernel_total - self._last_kernel_drop_total
                                    if delta > 0:
                                        self.stats['dropped'] += delta
                                        logger.warning(
                                            "Kernel UDP receive queue overflow detected; "
                                            "dropped +%d (total=%d)",
                                            delta,
                                            self.stats['dropped'],
                                        )
                                self._last_kernel_drop_total = kernel_total

                    # Always log the full raw line at DEBUG level
                    logger.debug(f"Raw syslog from {addr}: {raw_line!r}")

                    # For parsing, pass only the firewall part after the syslog header, if present
                    parsed_part = raw_line
                    if " - - " in raw_line:
                        parts = raw_line.split(" - - ", 1)
                        if len(parts) == 2:
                            parsed_part = parts[1].strip()

                    # Process the log (parsed_part for parser/dedup, raw_line for forwarding)
                    self._process_log(parsed_part, raw_line)
                    
                    # Print stats every 1000 logs
                    if self.stats['received'] % 1000 == 0:
                        self._print_stats()
                        
                except socket.error as e:
                    if self.running:
                        logger.error(f"Socket error: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error processing log: {e}")
                    self.stats['errors'] += 1
                    
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, shutting down...")
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Shutdown the server gracefully."""
        logger.info("Shutting down syslog server...")
        self.running = False
        if hasattr(self, "_ingest_catalog_refresh_stop"):
            self._ingest_catalog_refresh_stop.set()
        
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        
        if self.forwarder is not None:
            self.forwarder.close()
        self._print_stats()
        logger.info("Shutdown complete.")


def main():
    """Main entry point."""
    try:
        config = load_config()
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    server = SyslogServer(config)
    
    # Handle SIGINT and SIGTERM for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Received shutdown signal")
        server.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the server
    server.run()


if __name__ == '__main__':
    main()

