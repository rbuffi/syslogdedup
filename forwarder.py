"""Syslog forwarder for sending processed logs to downstream server."""
import logging
import socket
from typing import Optional, List
from parser import ParsedLog
from config import SyslogConfig


logger = logging.getLogger(__name__)


class SyslogForwarder:
    """Forwarder for sending enriched logs to downstream syslog server."""
    
    def __init__(self, config: SyslogConfig):
        """
        Initialize syslog forwarder.
        
        Args:
            config: SyslogConfig object with forwarding details
        """
        self.config = config
        self.socket = None
        self._connect()
    
    def _connect(self):
        """Establish socket connection to downstream syslog server."""
        try:
            if self.config.use_tcp:
                # TCP syslog
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.config.forward_host, self.config.forward_port))
                logger.info(
                    f"Initialized TCP syslog forwarder to "
                    f"{self.config.forward_host}:{self.config.forward_port}"
                )
            else:
                # UDP syslog (default)
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                logger.info(
                    f"Initialized UDP syslog forwarder to "
                    f"{self.config.forward_host}:{self.config.forward_port}"
                )
        except Exception as e:
            logger.error(f"Failed to create socket for syslog forwarding: {e}")
            self.socket = None
    
    def _format_log(
        self,
        log: ParsedLog,
        source_groups: Optional[List[str]] = None,
        dest_groups: Optional[List[str]] = None,
        raw_line: Optional[str] = None,
    ) -> str:
        """
        Format log with enriched group information.
        
        Args:
            log: ParsedLog object
            source_groups: List of NSX groups for source IP
            dest_groups: List of NSX groups for destination IP
            
        Returns:
            Formatted log string
        """
        # Use the full original syslog line if provided; fall back to parsed line
        base_line = raw_line if raw_line is not None else log.original_line

        # Build enriched log line
        parts = [base_line]
        
        # Add group information if available
        if source_groups:
            parts.append(f"src_groups={','.join(source_groups)}")
        if dest_groups:
            parts.append(f"dest_groups={','.join(dest_groups)}")
        
        return " | ".join(parts)
    
    def forward(
        self,
        log: ParsedLog,
        source_groups: Optional[List[str]] = None,
        dest_groups: Optional[List[str]] = None,
        raw_line: Optional[str] = None,
    ) -> bool:
        """
        Forward a log to the downstream syslog server.
        
        Args:
            log: ParsedLog object to forward
            source_groups: List of NSX groups for source IP
            dest_groups: List of NSX groups for destination IP
            
        Returns:
            True if forwarding succeeded, False otherwise
        """
        if not self.socket:
            logger.warning("Syslog forwarder socket not available, attempting to reconnect")
            self._connect()
            if not self.socket:
                return False
        
        try:
            formatted_log = self._format_log(log, source_groups, dest_groups, raw_line=raw_line)
            message = formatted_log.encode('utf-8')

            if self.config.use_tcp:
                # For TCP syslog, send with newline terminator
                if not formatted_log.endswith("\n"):
                    message += b"\n"
                self.socket.sendall(message)
            else:
                # UDP syslog
                self.socket.sendto(message, (self.config.forward_host, self.config.forward_port))

            return True

        except socket.error as e:
            logger.error(
                f"Failed to forward log to {self.config.forward_host}:{self.config.forward_port}: {e}"
            )
            # Attempt to reconnect on next call
            self.socket = None
            return False
        except Exception as e:
            logger.error(f"Unexpected error forwarding log: {e}")
            return False
    
    def close(self):
        """Close the syslog forwarder socket."""
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                logger.warning(f"Error closing syslog forwarder socket: {e}")
            finally:
                self.socket = None

