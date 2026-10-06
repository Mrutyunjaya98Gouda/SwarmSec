"""Trust scoring and corroboration logic for SwarmSec."""

from swarmsec.node.models import SwarmSecMessage
import urllib.parse

def get_pattern_entropy_weight(pattern: str) -> float:
    """
    Determine the entropy and specificity weight of a STIX pattern.
    High entropy (e.g., hashes, registry keys, mutexes) = 1.0 to 1.5
    Medium entropy (e.g., URLs, domains) = 0.8 to 1.2
    Low entropy (e.g., IP addresses) = 0.5 to 0.6
    """
    pattern_lower = pattern.lower()
    base_weight = 0.5
    
    # 1. Base Entity Entropy
    if "file:hashes" in pattern_lower or "sha-256" in pattern_lower or "md5" in pattern_lower:
        base_weight = 1.0
    elif "windows-registry-key" in pattern_lower or "mutex:name" in pattern_lower:
        base_weight = 1.2
    elif "url:value" in pattern_lower:
        base_weight = 0.8
    elif "domain-name:value" in pattern_lower:
        base_weight = 0.7
    elif "ipv4-addr:value" in pattern_lower or "ipv6-addr:value" in pattern_lower:
        base_weight = 0.5
        
    # 2. Specificity Multipliers
    multiplier = 1.0
    
    # Composite Indicators (AND combinations)
    if " and " in pattern_lower:
        multiplier *= 1.2
        
    # Deep URI paths
    if "url:value" in pattern_lower:
        import re
        urls = re.findall(r"url:value\s*=\s*'([^']+)'", pattern_lower)
        for u in urls:
            parsed = urllib.parse.urlparse(u)
            if parsed.path and len(parsed.path) > 1 and parsed.path != "/":
                multiplier *= 1.5
                break
                
    # Port constraints
    if "network-traffic:dst_port" in pattern_lower or "network-traffic:src_port" in pattern_lower:
        multiplier *= 1.2
        
    # TLS fingerprint / JARM
    if "x509-certificate:hashes" in pattern_lower or "jarm" in pattern_lower:
        multiplier *= 1.5

    return round(base_weight * multiplier, 2)


def compute_corroboration_score(
    messages: list[SwarmSecMessage], 
    feedbacks: list[SwarmSecMessage] = None,
    all_messages: dict = None,
    revoked_credentials: set[str] = None
) -> dict:
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
    seen_descriptions = []
    flags = set()
    
    independent_sources_count = 0
    score = 0.0
    
    # Sort messages by timestamp to process the "first" reporter first
    sorted_messages = sorted(messages, key=lambda m: m.envelope.timestamp)
    
    for msg in sorted_messages:
        cred_id = msg.envelope.credential_id
        
        if revoked_credentials and cred_id in revoked_credentials:
            continue
            
        # Deduplicate multiple messages from the same credential (they shouldn't exist due to 
        # rate limits or they just don't add corroboration value)
        if cred_id in seen_credentials:
            continue
            
        seen_credentials.add(cred_id)
        
        # Independence check: do they share the same external_reference URL/domain?
        is_independent = True
        has_references = False
        
        for ref in msg.payload.external_references:
            if ref.url:
                has_references = True
                domain = urllib.parse.urlparse(ref.url).netloc
                if not domain:
                    domain = ref.url
                    
                if domain in seen_feeds:
                    is_independent = False
                    flags.add("feed_overlap")
                else:
                    seen_feeds.add(domain)
                    
        desc = getattr(msg.payload, "description", "") or getattr(msg.payload, "name", "")
        if desc:
            desc_tokens = set(desc.lower().split())
            if desc_tokens:
                for seen_desc in seen_descriptions:
                    intersection = len(desc_tokens & seen_desc)
                    union = len(desc_tokens | seen_desc)
                    if union > 0 and (intersection / union) > 0.8:
                        is_independent = False
                        flags.add("semantic_overlap")
                seen_descriptions.append(desc_tokens)
                
        if independent_sources_count > 0 and not has_references:
            flags.add("missing_references_low_confidence")
            
        if is_independent:
            independent_sources_count += 1
            # Base score is 0 for the first source
            if independent_sources_count > 1:
                score += entropy_weight
                
    # Process feedback (Opinions)
    if feedbacks and all_messages:
        from swarmsec.node.feedback_graph import (
            build_endorsement_graph,
            get_feedback_weight,
        )
        graph, totals = build_endorsement_graph(all_messages)
        
        # Map indicator IDs and message IDs to their creators' credential IDs
        indicator_creators = {}
        for m in sorted_messages:
            indicator_creators[m.payload.id] = m.envelope.credential_id
            indicator_creators[m.envelope.message_id] = m.envelope.credential_id
            
        from datetime import datetime
        
        # Sort feedbacks chronologically to calculate inter-arrival velocity
        sorted_feedbacks = sorted(feedbacks, key=lambda f: f.envelope.timestamp)
        
        # Keep track of previous feedback time to detect bursts
        prev_feedback_dt = None
        
        for fb in sorted_feedbacks:
            giver_id = fb.envelope.credential_id
            
            if revoked_credentials and giver_id in revoked_credentials:
                continue
                
            sentiment = 1.0
            if fb.payload.opinion in ("disagree", "strongly-disagree"):
                sentiment = -1.0
            elif fb.payload.opinion == "neutral":
                sentiment = 0.0
            
            # Find the actual target credential ID for this specific feedback
            target_cred_id = None
            for ref in fb.payload.object_refs:
                if ref in indicator_creators:
                    target_cred_id = indicator_creators[ref]
                    break
                    
            if not target_cred_id:
                # Fallback to first reporter if we somehow can't match it
                target_cred_id = sorted_messages[0].envelope.credential_id
                
            if giver_id == target_cred_id or giver_id in seen_credentials:
                continue
                
            weight = get_feedback_weight(giver_id, target_cred_id, graph, totals)
            
            try:
                indicator_dt = datetime.fromisoformat(sorted_messages[0].envelope.timestamp.replace('Z', '+00:00'))
                feedback_dt = datetime.fromisoformat(fb.envelope.timestamp.replace('Z', '+00:00'))
                
                # 1. Vesting: Time since indicator published
                delta_since_publish = (feedback_dt - indicator_dt).total_seconds()
                time_decay = 0.5
                if delta_since_publish > 7 * 86400:
                    time_decay = 1.0
                elif delta_since_publish > 300:
                    fraction = (delta_since_publish - 300) / (7 * 86400 - 300)
                    time_decay = 0.5 + (0.5 * fraction)
                    
                # 2. Velocity: Time since previous feedback (burst penalty)
                burst_penalty = 1.0
                if prev_feedback_dt:
                    delta_since_prev = (feedback_dt - prev_feedback_dt).total_seconds()
                    if delta_since_prev < 3600:  # within 1 hour of another feedback
                        burst_penalty = 0.7  # 30% penalty for clustering tightly in time
                        flags.add("velocity_burst_penalty")
                        
                prev_feedback_dt = feedback_dt
                
            except Exception:
                time_decay = 0.5  # fallback if parsing fails
                burst_penalty = 1.0
                
            weight = weight * time_decay * burst_penalty
            
            if weight < 1.0:
                flags.add("feedback_downweighted")
                
            if weight > 0 and sentiment != 0.0:
                seen_credentials.add(giver_id)
                independent_sources_count += (1 if sentiment > 0 else 0)
                
                # Feedback weight depends on the entropy of the indicator and the graph penalty
                score += (entropy_weight * weight * sentiment)
                
    if independent_sources_count <= 1:
        status = "UNCONFIRMED — single source, awaiting corroboration"
    elif score >= 2.0:
        status = "CONFIRMED — high confidence"
    elif score >= 1.0:
        status = "CONFIRMED — medium confidence"
    else:
        status = "UNCONFIRMED — insufficient confidence score"
        
    return {
        "status": status,
        "local_corroboration_score": round(score, 2),
        "independent_sources": independent_sources_count,
        "flags": sorted(list(flags))
    }
