"""
authority_routing.py
--------------------
Track B authority-email routing (additive; Track A's admin letter flow is
untouched).

Lifecycle contract (a flip, NOT a new tier):
    pending -> verified        (authority email was delivered & confirmed,
                                re-usable for future emails)
    verified -> bounced        (the authority's inbox rejected the email:
                                unknown/removed/halted)
    bounced  -> pending        (flip back — a corrected email re-enters the
                                normal queue; nothing is ever deleted)

Routing decision: a resolved corroboration cluster is handed to ONE authority.
If the owning authority for the coarse area + hazard is `verified`, the email
is auto-sent by the driver. Otherwise (unowned / pending / bounced) the
cluster is placed on the admin authority-email queue so a human types or
corrects the address — we never silently drop it and never auto-guess.

No state is duplicated: authority lifecycle lives in the `authorities` table;
the routing decision is derived at call time from (authority_area_key,
hazard_type) + the cluster's corroboration state.
"""

from datetime import datetime, timezone

import db

# ---------------------------------------------------------------------------
# RFC-ish guard: refuse to auto-send when the address itself is bogus.
# ---------------------------------------------------------------------------
def _looks_bogus(email):
    email = (email or "").strip()
    if not email or "@" not in email:
        return True
    local, _, domain = email.partition("@")
    if not local or "." not in domain or " " in email:
        return True
    return False


# ---------------------------------------------------------------------------
# Lookup helpers (thin db passthroughs)
# ---------------------------------------------------------------------------
def get_authority(authority_id):
    return db.get_authority(authority_id)


def list_authorities_for_admin():
    return db.list_authorities()


def resolve_owner(authority_area_key, hazard_type):
    """Best current authority for the coarse area + hazard (derived at call
    time from the authorities table). Returns None when unowned."""
    return db.get_verified_authority(authority_area_key, hazard_type)


# ---------------------------------------------------------------------------
# Lifecycle transitions (flip, not a new tier)
# ---------------------------------------------------------------------------
def verify_authority(authority_id):
    """pending/verified -> verified (confirm the typed address is deliverable)."""
    db.mark_authority_verified(authority_id)


def bounce_authority(authority_id, reason=None):
    """verified -> bounced -> pending. Flip: the row stays, lifecycle flips."""
    db.mark_authority_bounced(authority_id, reason=reason)


# ---------------------------------------------------------------------------
# Routing decision
# ---------------------------------------------------------------------------
def route_cluster(cluster):
    """Decide where a resolved corroboration cluster goes:

    Returns a decision dict:
      {
        "channel": "auto_email"  -> verified owner + non-bogus address; the
                                    driver sends now.
                 | "admin_queue" -> unowned / pending / bounced / bogus;
                                    surface on the admin authority-email queue.
        "owner": <authority row or None>,
        "reason": short human string,
      }
    """
    owner = resolve_owner(cluster["authority_area_key"], cluster["hazard_type"])
    if owner is None:
        return {"channel": "admin_queue",
                "owner": None,
                "reason": "no_verified_authority_for_area"}
    if owner["lifecycle"] != "verified":
        return {"channel": "admin_queue",
                "owner": owner,
                "reason": "authority_not_verified"}
    if _looks_bogus(owner["email"]):
        return {"channel": "admin_queue",
                "owner": owner,
                "reason": "bogus_email_guard"}
    return {"channel": "auto_email", "owner": owner, "reason": "verified_owner"}

def route_pending_clusters():
    try:
        from corroboration import run_lifecycle_sweep as _s
        if callable(_s):
            return _s()
    except Exception:
        pass
    return 0

