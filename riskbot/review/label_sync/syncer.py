from typing import Dict, Any, List

# Label colors (consistent branding)
LABEL_COLORS = {
    "P0": "d73a4a",  # Red
    "P1": "fbca04",  # Yellow
    "P2": "0e8a16"   # Green
}

LABEL_DESCRIPTIONS = {
    "P0": "RiskBot review priority: Immediate (high risk)",
    "P1": "RiskBot review priority: Normal",
    "P2": "RiskBot review priority: Low (safe to skim)"
}

def sync_labels(
    provider,
    pr_number: int,
    priority: str,
    config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Sync PR labels based on review priority.
    Idempotent: running twice with same priority makes no changes.
    
    Args:
        provider: LabelSyncProvider implementation
        pr_number: PR/MR number
        priority: P0 | P1 | P2
        config: Label sync config
        
    Returns:
        Dict with sync results (added, removed, errors)
    """
    result = {"added": [], "removed": [], "errors": []}
    
    # Get config
    label_map = config.get("labels", {
        "P0": "risk:P0",
        "P1": "risk:P1",
        "P2": "risk:P2"
    })
    
    cleanup = config.get("cleanup_other_priority_labels", True)
    create_if_missing = config.get("create_if_missing", True)
    dry_run = config.get("dry_run", False)
    
    # Determine desired label
    desired_label = label_map.get(priority)
    if not desired_label:
        result["errors"].append(f"No label mapping for priority {priority}")
        return result
    
    # All priority labels (for cleanup)
    all_priority_labels = set(label_map.values())
    
    # Create label if needed
    if create_if_missing and not dry_run:
        try:
            color = LABEL_COLORS.get(priority, "cccccc")
            description = LABEL_DESCRIPTIONS.get(priority, "")
            provider.ensure_label_exists(desired_label, color, description)
        except Exception as e:
            result["errors"].append(f"Could not create label: {e}")
    
    # Get existing labels
    try:
        existing_labels = set(provider.get_labels(pr_number))
    except Exception as e:
        result["errors"].append(f"Could not fetch labels: {e}")
        return result
    
    # Compute changes (idempotent algorithm)
    # to_remove = (existing ∩ priority_labels) - {desired}
    # to_add = {desired} - existing
    
    to_remove = []
    if cleanup:
        to_remove = list((existing_labels & all_priority_labels) - {desired_label})
        to_remove.sort()  # Deterministic ordering
    
    to_add = []
    if desired_label not in existing_labels:
        to_add = [desired_label]
    
    # Debug output (helpful for troubleshooting)
    if config.get("debug", False):
        print(f"Debug - Existing labels: {sorted(existing_labels)}")
        print(f"Debug - To add: {to_add}")
        print(f"Debug - To remove: {to_remove}")
    
    # Apply changes (or show dry-run)
    if dry_run:
        result["dry_run"] = True
        result["would_add"] = to_add
        result["would_remove"] = to_remove
        result["no_changes"] = (not to_add and not to_remove)
    else:
        # Remove old priority labels
        if to_remove:
            try:
                provider.remove_labels(pr_number, to_remove)
                result["removed"] = to_remove
            except Exception as e:
                result["errors"].append(f"Could not remove labels: {e}")
        
        # Add desired label if missing
        if to_add:
            try:
                provider.add_labels(pr_number, to_add)
                result["added"] = to_add
            except Exception as e:
                result["errors"].append(f"Could not add label: {e}")
        
        # Track if no changes were needed
        result["no_changes"] = (not to_add and not to_remove)
        result["current_label"] = desired_label
    
    return result
