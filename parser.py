"""Log parser for firewall log format from VMware Log Insight."""
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ParsedLog:
    """Structured representation of a parsed firewall log."""
    timestamp_id: str
    network_type: str
    action: str
    result: str
    rule_id: str
    direction: str
    size_id: str
    protocol: str
    source_ip: str
    source_port: str
    dest_ip: str
    dest_port: str
    rule_name: str
    original_line: str


class LogParser:
    """Parser for firewall log format."""
    
    # Pattern to match: <id> <type> <action> <result> <rule_id> <direction> <size> <protocol> <src_ip/port>-><dest_ip/port> <rule_name>
    # Example: 7c11f001 INET match PASS 8225 OUT 73 UDP 10.10.10.10/42017->20.20.20.20/53 SZ-TRF_CATCH_ALL1111_TFRC6-6_Server_B
    LOG_PATTERN = re.compile(
        r'^(\S+)\s+'  # timestamp/id
        r'(\S+)\s+'   # network_type (INET)
        r'(\S+)\s+'   # action (match)
        r'(\S+)\s+'   # result (PASS)
        r'(\S+)\s+'   # rule_id
        r'(\S+)\s+'   # direction (OUT/IN)
        r'(\S+)\s+'   # size/id
        r'(\S+)\s+'   # protocol (UDP/TCP)
        r'(\S+)/(\d+)->(\S+)/(\d+)\s+'  # source_ip/port->dest_ip/port
        r'(.+)$'      # rule_name (rest of the line)
    )
    # Some TERM logs omit the size field and include extra counters after the ports, e.g.:
    # 6be61891 INET TERM PASS 5112 IN UDP 10.222.22.1/62824->10.222.29.255/1947 1/0 68/0 SZ-...
    LOG_PATTERN_TERM = re.compile(
        r'^(\S+)\s+'  # timestamp/id
        r'(\S+)\s+'   # network_type (INET)
        r'(\S+)\s+'   # action (TERM)
        r'(\S+)\s+'   # result (PASS)
        r'(\S+)\s+'   # rule_id
        r'(\S+)\s+'   # direction (IN/OUT)
        r'(\S+)\s+'   # protocol (UDP/TCP)
        r'(\S+)/(\d+)->(\S+)/(\d+)'  # source_ip/port->dest_ip/port
        r'(?:\s+\S+/\S+\s+\S+/\S+)?'  # optional extra counters like "1/0 68/0"
        r'\s+(.+)$'   # rule_name (rest of the line)
    )
    
    @staticmethod
    def parse(log_line: str) -> Optional[ParsedLog]:
        """
        Parse a firewall log line.
        
        Args:
            log_line: Raw log line string
            
        Returns:
            ParsedLog object if parsing succeeds, None otherwise
        """
        if not log_line or not log_line.strip():
            return None
        
        # Remove any trailing newlines/whitespace. At this point we expect only
        # the firewall-specific part (header stripping is done in main.py).
        log_line = log_line.strip()

        # First try the full pattern (with size field)
        match = LogParser.LOG_PATTERN.match(log_line)
        if match:
            try:
                return ParsedLog(
                    timestamp_id=match.group(1),
                    network_type=match.group(2),
                    action=match.group(3),
                    result=match.group(4),
                    rule_id=match.group(5),
                    direction=match.group(6),
                    size_id=match.group(7),
                    protocol=match.group(8),
                    source_ip=match.group(9),
                    source_port=match.group(10),
                    dest_ip=match.group(11),
                    dest_port=match.group(12),
                    rule_name=match.group(13),
                    original_line=log_line
                )
            except (IndexError, AttributeError):
                return None

        # Fallback: TERM-style pattern without size, with extra counters
        match_term = LogParser.LOG_PATTERN_TERM.match(log_line)
        if match_term:
            try:
                return ParsedLog(
                    timestamp_id=match_term.group(1),
                    network_type=match_term.group(2),
                    action=match_term.group(3),
                    result=match_term.group(4),
                    rule_id=match_term.group(5),
                    direction=match_term.group(6),
                    size_id="",  # size not present in this variant
                    protocol=match_term.group(7),
                    source_ip=match_term.group(8),
                    source_port=match_term.group(9),
                    dest_ip=match_term.group(10),
                    dest_port=match_term.group(11),
                    rule_name=match_term.group(12),
                    original_line=log_line
                )
            except (IndexError, AttributeError):
                return None

        # No pattern matched
        return None

