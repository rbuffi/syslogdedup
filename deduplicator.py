"""Deduplication logic for firewall logs."""
from typing import Set
from parser import ParsedLog


class Deduplicator:
    """In-memory duplicate detection based on key fields."""
    
    def __init__(self):
        """Initialize the deduplicator with an empty set of seen log keys."""
        self._seen_keys: Set[str] = set()
    
    def _generate_key(self, log: ParsedLog) -> str:
        """
        Generate a unique key for duplicate detection.
        
        Key fields: source IP, destination IP, source port, destination port, protocol
        
        Args:
            log: ParsedLog object
            
        Returns:
            String key for duplicate detection
        """
        return f"{log.source_ip}:{log.source_port}:{log.dest_ip}:{log.dest_port}:{log.protocol}"
    
    def is_duplicate(self, log: ParsedLog) -> bool:
        """
        Check if a log is a duplicate based on key fields.
        
        Args:
            log: ParsedLog object to check
            
        Returns:
            True if duplicate, False if unique
        """
        key = self._generate_key(log)
        if key in self._seen_keys:
            return True
        
        # Mark as seen
        self._seen_keys.add(key)
        return False
    
    def reset(self):
        """Reset the deduplicator (clear all seen keys)."""
        self._seen_keys.clear()
    
    def get_seen_count(self) -> int:
        """
        Get the number of unique log entries seen.
        
        Returns:
            Number of unique log entries
        """
        return len(self._seen_keys)

