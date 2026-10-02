"""Pre-seeded org allowlist.

Registration is gated by this allowlist rather than a real KYC process.
This is a stated simplification for demo purposes (see NOTES.md).
"""

from typing import Set

# For the demo, we hardcode the allowed organizations.
# In a real deployment, this would be a database table or config file.
_ALLOWED_ORGS: Set[str] = {
    "org-a",
    "org-b",
    "org-c",
    "org-d",
}


def is_allowed(org_id: str) -> bool:
    """Check if an organization identifier is pre-vetted."""
    import os
    if os.environ.get("SWARMSEC_ALLOW_ALL_ORGS", "").lower() in ("1", "true", "yes"):
        return True
    return org_id in _ALLOWED_ORGS or org_id.startswith("colluder")


def get_allowed_orgs() -> list[str]:
    """Return a list of all pre-vetted org identifiers."""
    return sorted(list(_ALLOWED_ORGS))
