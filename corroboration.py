"""
corroboration.py
----------------
Track B count-free corroboration engine.

Every count is DERIVED at read time:
    COUNT(DISTINCT detections.client_ip)
per fine grid cell + hazard + time window — there is NO stored counter, no
stored count column anywhere flags. The area keys themselves are DERIVED
(not stored in a way that Track A needs to know about) from each row's
lat/lon at insert time.

Grid model (both keys derived from lat/lon, env-configurable precision):
- FINE key   "corroboration_area_key":  ~111 m cells (=> localised, single
  road/pavement cluster). Used to group citizen reports that are effectively
  the same stretch of damage.
- COARSE key "authority_area_key":     ~1.1 km cells (=> correlates to the
  authority that owns that jurisdiction). ONE per citizen report; used to
  route to the authority owning that ~1 km territory.

Windows: fixed windows (UTC) of envconfigurable length (default 2 h). A
cluster is "mature/resolvable" once window_start + window_len has elapsed;
only matured windows are ever escalated to corroborated -> letter -> email.
"""

import math
import os
import time
from datetime import datetime, timezone, timedelta

import db

# --- config surfaces (env, all optional, with safe defaults) -----------------
FINE_DECIMALS = int(os.environ.get("CORROBORATION_FINE_DECIMALS", "3"))    # ~111 m
COARSE_DECIMALS = int(os.environ.get("CORROBORATION_COARSE_DECIMALS", "2"))  # ~1.1 km
WINDOW_SECONDS = int(os.environ.get("CORROBORATION_WINDOW_SECONDS", str(2 * 3600)))
CORROBORATION_THRESHOLD = int(os.environ.get("CORROBORATION_THRESHOLD", "3"))
HAZARD_TYPE = os.environ.get("CORROBORATION_HAZARD_TYPE", "road_damage")

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _round_cell(value, decimals):
    """Round a lat/lon to a fixed cell precision (deterministic cell key)."""
    return round(value, decimals)


def fine_area_key(lat, lon):
    """~111 m cell key. None when lat/lon missing (nothing corroborates then)."""
    if lat is None or lon is None:
        return None
    return f"{_round_cell(lat, FINE_DECIMALS)}:{_round_cell(lon, FINE_DECIMALS)}"


def coarse_area_key(lat, lon):
    """~1.1 km cell key -> correlates to the owning authority's territory."""
    if lat is None or lon is None:
        return None
    return f"{_round_cell(lat, COARSE_DECIMALS)}:{_round_cell(lon, COARSE_DECIMALS)}"


def window_start_of(dt):
    """Floor dt to the corroboration window (UTC)."""
    ts = int(dt.timestamp())
    start = ts - (ts % WINDOW_SECONDS)
    return datetime.fromtimestamp(start, tz=timezone.utc)


def window_end_of(window_start):
    return window_start + timedelta(seconds=WINDOW_SECONDS)


def window_matured(window_start):
    """A window is only actionable after it has fully elapsed."""
    return datetime.now(timezone.utc) >= window_end_of(window_start)


def cluster_rows(fine_key, hazard_type, window_start):
    """All citizen reports (server-captured client_ip set) that fall in the
    fine cell + hazard + window. The corroboration count is DERIVED per call:
        COUNT(DISTINCT client_ip) on this result set.
    """
    conn = db.get_conn()
    rows = conn.execute(
        """
        SELECT client_ip, created_at
        FROM detections
        WHERE corroboration_area_key = ?
          AND hazard_type = ?
          AND status IN ('pending', 'approved')
          AND created_at >= ? AND created_at < ?
        """,
        (fine_key, hazard_type, window_start.isoformat(), window_end_of(window_start).isoformat()),
    ).fetchall()
    conn.close()
    return rows


def corroboration_count(fine_key, hazard_type, window_start):
    """ALWAYS derived: COUNT(DISTINCT client_ip) over the cluster rows.
    Never read from a stored counter."""
    rows = [r for r in cluster_rows(fine_key, hazard_type, window_start) if r["client_ip"]]
    return len({r["client_ip"] for r in rows})


def cluster_lifecycle(fine_key, hazard_type, window_start):
    """Derive the cluster's corroboration lifecycle on demand:
    open / corroborated / emailed / settled. Purely a function of the
    derived count, the elapsed window and the corroboration_clusters row."""
    row = db.get_cluster(fine_key, hazard_type, window_start)
    count = corroboration_count(fine_key, hazard_type, window_start)
    if row is None:
        if count >= CORROBORATION_THRESHOLD and window_matured(window_start):
            db.put_cluster(fine_key, hazard_type, window_start)
            return cluster_lifecycle(fine_key, hazard_type, window_start)
        return "open"

    lifecycle = row["lifecycle"]
    # counts always truth; re-derive (no stored counter to trust)
    if count >= CORROBORATION_THRESHOLD and window_matured(window_start):
        if lifecycle in ("open", "corroborated"):
            return "corroborated"
    if lifecycle == "emailed":
        return "emailed"
    if lifecycle in ("settled", "corroborated", "emailed") and count < CORROBORATION_THRESHOLD:
        # never crosses back automatically; state machine owns resets
        return "settled"
    return lifecycle


def offending_clusters():
    """Clusters with a matured window + corroborated count that still need an
    authority notification (derived count over maturity). Returns fine keys
    whose derived count crossed CORROBORATION_THRESHOLD in an elapsed window."""
    conn = db.get_conn()
    rows = conn.execute(
        """
        SELECT corroboration_area_key AS fine_key, hazard_type,
               window_start
        FROM detections
        """,
    ).fetchall()
    conn.close()

    seen = set()
    offenders = []
    for row in rows:
        key = (row["fine_key"], row["hazard_type"], row["window_start"])
        if key in seen or row["fine_key"] is None:
            continue
        seen.add(key)
        ws = datetime.fromisoformat(row["window_start"])
        if window_matured(ws):
            count = corroboration_count(*key)
            if count >= CORROBORATION_THRESHOLD:
                offenders.append(row)
    return offenders


def fine_key_from_row(detection_row):
    """Derive the fine corroboration key directly from a stored detection row's
    lat/lon (rows keep lat/lon, we never persist a redundant key on Track A)."""
    return fine_area_key(detection_row["lat"], detection_row["lon"])

def run_lifecycle_sweep():
    try:
        from lifecycle_sweep import run_lifecycle_sweep as _sweep
        return _sweep()
    except Exception:
        return 0



def list_clusters():
    try:
        from lifecycle_sweep import list_clusters as _delegated
        if callable(_delegated):
            return _delegated() or []
    except Exception:
        pass
    try:
        import db as _db
        if callable(getattr(_db, "list_clusters", None)):
            rows = _db.list_clusters()
            return rows or []
    except Exception:
        pass
    return []

