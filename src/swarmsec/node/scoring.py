"""Trust scoring and corroboration logic for SwarmSec."""

from typing import List

from swarmsec.node.models import SwarmSecMessage


def get_pattern_entropy_weight(pattern: str) -> float:
    """
    Determine the entropy weight of a STIX pattern.
    High entropy (e.g., specific hashes) = 1.0
    Medium entropy (e.g., URLs, domains) = 0.8
    Low entropy (e.g., IP addresses) = 0.5
    """
    pattern_lower = pattern.lower()
    if "file:hashes" in pattern_lower or "sha-256" in pattern_lower or "md5" in pattern_lower:
        return 1.0
    if "url:value" in pattern_lower or "domain-name:value" in pattern_lower:
        return 0.8
    if "ipv4-addr:value" in pattern_lower or "ipv6-addr:value" in pattern_lower:
        return 0.5
    
    # Default to low entropy if unknown
    return 0.5


def compute_corroboration_score(messages: List[SwarmSecMessage]) -> dict:
    """
    Compute the local corroboration score for a set of messages reporting the same indicator.
    
    Implements the fixed-parameter formula:
    1. Base score for a single source = 0.
    2. Additional sources (independent) add weight based on pattern entropy.
    3. Overlapping external_references flag as not independent (weight = 0).
    """
    if not messages:
        return {
            "status": "UNKNOWN",
            "local_corroboration_score": 0.0,
            "independent_sources": 0,
            "flags": []
        }
        
    pattern = messages[0].payload.pattern
    entropy_weight = get_pattern_entropy_weight(pattern)
    
    seen_credentials = set()
    seen_feeds = set()
    flags = set()
    
    independent_sources_count = 0
    score = 0.0
    
    # Sort messages by timestamp to process the "first" reporter first
    sorted_messages = sorted(messages, key=lambda m: m.envelope.timestamp)
    
    for msg in sorted_messages:
        cred_id = msg.envelope.credential_id
        
        # Deduplicate multiple messages from the same credential (they shouldn't exist due to 
        # rate limits or they just don't add corroboration value)
        if cred_id in seen_credentials:
            continue
            
        seen_credentials.add(cred_id)
        
        # Independence check: do they share the same external_reference URL?
        is_independent = True
        for ref in msg.payload.external_references:
            if ref.url:
                if ref.url in seen_feeds:
                    is_independent = False
                    flags.add("feed_overlap")
                else:
                    seen_feeds.add(ref.url)
                    
        if is_independent:
            independent_sources_count += 1
            # Base score is 0 for the first source
            if independent_sources_count > 1:
                score += entropy_weight
                
    if independent_sources_count <= 1:
        status = "UNCONFIRMED — single source, awaiting corroboration"
    else:
        status = "CONFIRMED"
        
    return {
        "status": status,
        "local_corroboration_score": round(score, 2),
        "independent_sources": independent_sources_count,
        "flags": sorted(list(flags))
    }
