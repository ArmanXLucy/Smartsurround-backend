"""
lifecycle_sweep.py
------------------
Track B orchestrator: corroboration sweep -> authority routing -> email.

This module is intentionally a thin coordinator. All the *logic* lives in the
existing modules and is called, never re-implemented:
  - corroboration.py: window_start_of / window_matured / corroboration_count
    (COUNT(DISTINCT client_ip), always derived) and the fine/coarse key rules
  - authority_routing.py: route_cluster (verified owner -> auto_email, else
    admin_queue) and the lifecycle flips
  - email_driver.py: send_authority_email (single outbound seam; test mode
    suppresses the actual send and overrides to EMAIL_TEST_RECIPIENT)
  - letter_generator.py: generate_letter(detection) -> letter PDF path

The sweep derives the candidate set of matured, corroborated
(fine key, hazard, window) groups itself with a small SELECT, because
corroboration.offending_clusters() references a `window_start` column that
does not exist on the live `detections` schema. Everything else reuses the
existing corroboration/routing surfaces verbatim.

Idempotent: a cluster already `emailed`/`settled` is skipped, so the repeated
touchpoints in the request cycle (upload + approve both sweep) never re-send.
"""

import logging
from datetime import datetime, timezone

import db
import corroboration
import authority_routing
import email_driver
import letter_generator

logger = logging.getLogger("smart_surround.lifecycle")


def _offender_contexts():
    """Candidate (fine_key, hazard_type, window_start) groups that have any
    pending/approved detections. Thin enumeration only — the actual sum
    decision (maturity + threshold over the DERIVED distinct-IP count) is
    deferred to corroboration.py in run_lifecycle_sweep()."""
    conn = db.get_conn()
    try:
        rows = conn.execute(
            """
            SELECT corroboration_area_key, hazard_type, client_ip, created_at
            FROM detections
            WHERE corroboration_area_key IS NOT NULL
              AND hazard_type IS NOT NULL
              AND status IN ('pending', 'approved')
            """
        ).fetchall()
    finally:
        conn.close()

    groups = {}  # (fine_key, hazard, window_start) -> date seen first
    for row in rows:
        try:
            created = datetime.fromisoformat(row["created_at"])
        except Exception:
            continue
        if not row["client_ip"]:
            continue
        ws = corroboration.window_start_of(created)
        key = (row["corroboration_area_key"], row["hazard_type"], ws)
        groups.setdefault(key, created)

    return [
        {"fine_key": fine_key, "hazard_type": hazard_type, "window_start": ws}
        for (fine_key, hazard_type, ws) in sorted(groups)
    ]


def _representative_detection(fine_key, hazard_type, window_start):
    """One detection row inside the cluster window (for the letter PDF + the
    routing decision's coarse key). Oldest qualifying row = the cluster seed."""
    conn = db.get_conn()
    try:
        row = conn.execute(
            """
            SELECT * FROM detections
            WHERE corroboration_area_key = ?
              AND hazard_type = ?
              AND status IN ('pending', 'approved')
              AND created_at >= ? AND created_at < ?
            ORDER BY id ASC LIMIT 1
            """,
            (
                fine_key,
                hazard_type,
                window_start.isoformat(),
                corroboration.window_end_of(window_start).isoformat(),
            ),
        ).fetchone()
    finally:
        conn.close()
    return row


def _compose_subject(hazard_type, authority_area_key):
    return (
        f"SmartSurround Road-Damage Authority Notice - "
        f"{hazard_type} (area {authority_area_key})"
    )


def _compose_body(rep, count, fine_key, window_start):
    lat = f"{rep['lat']:.6f}" if rep["lat"] is not None else "N/A"
    lon = f"{rep['lon']:.6f}" if rep["lon"] is not None else "N/A"
    severity = rep["severity"] or "N/A"
    damage_class = rep["damage_class"] or "Unclassified damage"
    return (
        "SmartSurround corroboration notice - road damage requiring attention.\n\n"
        f"Authority area (coarse key):   {rep['authority_area_key']}\n"
        f"Fine corroboration area:       {fine_key}\n"
        f"Corroboration window:          {window_start.isoformat()}\n"
        f"Distinct citizen reports:      {count}\n"
        f"Hazard type:                   {rep['hazard_type']}\n"
        f"Damage class:                  {damage_class}\n"
        f"Severity:                      {severity}\n"
        f"Coordinates:                   lat {lat}, lon {lon}\n\n"
        "Please find the generated authority letter attached."
    )


def run_lifecycle_sweep():
    """Walk matured, corroborated windows and route/email each one. Returns the
    number of clusters marked emailed this sweep. Never raises."""
    emailed = 0
    for ctx in _offender_contexts():
        try:
            fine_key = ctx["fine_key"]
            hazard_type = ctx["hazard_type"]
            ws = ctx["window_start"]

            if not corroboration.window_matured(ws):
                continue
            count = corroboration.corroboration_count(fine_key, hazard_type, ws)
            if count < corroboration.CORROBORATION_THRESHOLD:
                continue

            cluster = db.get_or_create_cluster(fine_key, hazard_type, ws.isoformat())
            if cluster["lifecycle"] in ("emailed", "settled"):
                continue

            rep = _representative_detection(fine_key, hazard_type, ws)
            if rep is None:
                continue

            decision = authority_routing.route_cluster(
                {"authority_area_key": rep["authority_area_key"],
                 "hazard_type": hazard_type}
            )
            if decision["channel"] != "auto_email":
                db.update_cluster(cluster["id"], lifecycle="corroborated")
                continue

            letter_path = letter_generator.generate_letter(rep)
            result = email_driver.send_authority_email(
                decision["owner"]["email"],
                _compose_subject(hazard_type, rep["authority_area_key"]),
                _compose_body(rep, count, fine_key, ws),
                letter_path,
            )
            if result.get("ok"):
                db.update_cluster(
                    cluster["id"],
                    lifecycle="emailed",
                    letter_path=letter_path,
                    emailed_at=datetime.now(timezone.utc).isoformat(),
                )
                emailed += 1
            else:
                db.update_cluster(cluster["id"], lifecycle="corroborated")
        except Exception as exc:  # never break the request cycle
            logger.warning("lifecycle sweep skipped a cluster: %s", exc)
    return emailed


def list_clusters():
    """Admin surface delegate (matches corroboration.list_clusters fallback)."""
    return db.list_clusters()