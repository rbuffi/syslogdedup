#!/usr/bin/env python3
"""Main syslog server for receiving, deduplicating, and forwarding firewall logs."""
import logging
import signal
import socket
import sys
from config import load_config, Config
from parser import LogParser
from deduplicator import Deduplicator
from nsxt_client import NSXTClient
from forwarder import SyslogForwarder
from influx_client import InfluxClient


# Configure logging (console)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

# Add a file logger specifically for NSX group debugging
_nsx_file_handler = logging.FileHandler("nsx_groups.log")
_nsx_file_handler.setLevel(logging.DEBUG)
_nsx_file_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
logging.getLogger("nsxt_client").addHandler(_nsx_file_handler)

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
        self.nsxt_client = NSXTClient(config.nsxt)
        self.forwarder = SyslogForwarder(config.syslog)
        self.influx_client = InfluxClient(config.influx)
        self.socket = None
        self.running = False
        
        # Statistics
        self.stats = {
            'received': 0,
            'parsed': 0,
            'duplicates': 0,
            'forwarded': 0,
            'errors': 0
        }
    
    def _setup_socket(self):
        """Create and bind UDP socket."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.config.syslog.listen_port))
            logger.info(f"Syslog server listening on UDP port {self.config.syslog.listen_port}")
        except PermissionError:
            logger.error(f"Permission denied: Cannot bind to port {self.config.syslog.listen_port}. "
                        f"Try running with sudo or use a port >= 1024")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to setup socket: {e}")
            sys.exit(1)
    
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
        
        try:
            source_groups = self.nsxt_client.lookup_ip_groups(parsed_log.source_ip)
            if source_groups is not None and len(source_groups) == 0:
                source_groups = None
        except Exception as e:
            logger.warning(f"Failed to lookup source IP {parsed_log.source_ip} in NSX-T: {e}")
        
        try:
            dest_groups = self.nsxt_client.lookup_ip_groups(parsed_log.dest_ip)
            if dest_groups is not None and len(dest_groups) == 0:
                dest_groups = None
        except Exception as e:
            logger.warning(f"Failed to lookup destination IP {parsed_log.dest_ip} in NSX-T: {e}")
        
        # Forward the enriched log, but keep the original syslog header/line
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
    
    def _print_stats(self):
        """Print statistics."""
        logger.info(f"Stats - Received: {self.stats['received']}, "
                   f"Parsed: {self.stats['parsed']}, "
                   f"Duplicates: {self.stats['duplicates']}, "
                   f"Forwarded: {self.stats['forwarded']}, "
                   f"Errors: {self.stats['errors']}")
    
    def run(self):
        """Run the syslog server main loop."""
        self._setup_socket()
        self.running = True
        
        logger.info("Syslog server started. Press Ctrl+C to stop.")
        
        try:
            while self.running:
                try:
                    # Receive UDP packet (max 65507 bytes for UDP)
                    data, addr = self.socket.recvfrom(65507)
                    raw_line = data.decode('utf-8', errors='replace')

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
        
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        
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

