"""
db.py
-----
Tiny SQLite layer for the detection / verification queue, plus the
Track B corroboration + authority-routing surfaces (all additive).

Track A (detection -> admin verify -> letter PDF) is untouched: the
`detections` table keeps every existing column and workflow.

Track B adds, without touching Track A:
- `detections.client_ip`            - citizen's corroboration identity (server
                                     captured from request hop X-Forwarded-For /
                                     remote_addr; NEVER a form field)
- `detections.hazard_type`          - default 'road_damage'; groups corroboration
                                     clusters and authority routing
- `detections.corroboration_area_key` - fine grid key (~111 m cells), one per
                                     citizen report; corroboration clusters group
                                     on it
- `detections.authority_area_key`   - coarse grid key (~1.1 km cells), one per
                                     report; correlates to the authority that
                                     owns that jurisdiction
- `authorities`                     - one row per typed/verified authority email
                                     for an area + hazard: lifecycle
                                     pending -> verified, or verified -> bounced
                                     -> pending (flip, not a new tier)
- `corroboration_clusters`          - corroboration state per (fine area,
                                     hazard_type, window). Count is ALWAYS derived
                                     (COUNT(DISTINCT client_ip)) on demand — no
                                     stored counter, no stored count column.
"""

import sqlite3
import os
import math
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "smartsurround.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _has_column(conn, table, column):
    cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    return column in cols


def _add_column(conn, table, ddl):
    if not _has_column(conn, table, ddl.split()[0]):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def init_db():
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            image_path TEXT NOT NULL,
            source TEXT NOT NULL,            -- 'esp32' or 'citizen'
            damage_class TEXT,
            confidence REAL,
            severity TEXT,                   -- Normal / Warning / Critical
            lat REAL,
            lon REAL,
            description TEXT,                -- optional citizen-provided note
            status TEXT NOT NULL DEFAULT 'pending',  -- pending/approved/rejected/letter_sent
            ai_accepted INTEGER,             -- 1 if the model's confidence cleared
                                             -- ACCEPT_THRESHOLD (detector.py's
                                             -- conservative decision layer), else 0
            created_at TEXT NOT NULL,
            reviewed_at TEXT,
            letter_path TEXT
        )
        """
    )

    # --- Track B (additive, guarded so existing DBs migrate, never break) ---
    _add_column(conn, "detections",
                "client_ip TEXT")                     # server-captured corroboration identity
    _add_column(conn, "detections",
                "hazard_type TEXT DEFAULT 'road_damage'")
    _add_column(conn, "detections",
                "corroboration_area_key TEXT")        # fine grid key (~111 m cells)
    _add_column(conn, "detections",
                "authority_area_key TEXT")            # coarse grid key (~1.1 km cells)

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS authorities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            authority_area_key TEXT NOT NULL,
            hazard_type TEXT NOT NULL,
            email TEXT NOT NULL,
            lifecycle TEXT NOT NULL DEFAULT 'pending',  -- pending/verified/bounced
            created_at TEXT NOT NULL,
            verified_at TEXT,
            bounced_at TEXT,
            bounce_reason TEXT,
            UNIQUE(authority_area_key, hazard_type, email)
        )
        """
    )



    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT NOT NULL UNIQUE,
            user_id TEXT NOT NULL,
            user_name TEXT,
            email TEXT,
            subject TEXT NOT NULL,
            description TEXT NOT NULL,
            priority TEXT NOT NULL DEFAULT 'Normal',
            attachment_path TEXT,
            status TEXT NOT NULL DEFAULT 'Open',
            admin_reply TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            category TEXT,
            incident_latitude REAL,
            incident_longitude REAL,
            incident_accuracy REAL,
            incident_gps_time TEXT,
            verified_by TEXT,
            verified_at TEXT,
            verification_notes TEXT,
            environment_snapshot_json TEXT
        )
        """
    )
    for ddl in (
        "category TEXT",
        "incident_latitude REAL",
        "incident_longitude REAL",
        "incident_accuracy REAL",
        "incident_gps_time TEXT",
        "verified_by TEXT",
        "verified_at TEXT",
        "verification_notes TEXT",
        "environment_snapshot_json TEXT",
    ):
        _add_column(conn, "complaints", ddl)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS corroboration_clusters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            corroboration_area_key TEXT NOT NULL,
            hazard_type TEXT NOT NULL,
            window_start TEXT NOT NULL,
            lifecycle TEXT NOT NULL DEFAULT 'open',     -- open/corroborated/emailed/settled
            letter_path TEXT,
            emailed_at TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(corroboration_area_key, hazard_type, window_start)
        )
        """
    )


    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            name TEXT,
            email TEXT,
            phone TEXT,
            department TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            status TEXT NOT NULL DEFAULT 'Idle',
            account_status TEXT NOT NULL DEFAULT 'Enabled',
            device_id TEXT,
            created_at TEXT NOT NULL,
            last_active TEXT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            accuracy REAL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'working',
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_user_locations_user_time
        ON user_locations(user_id, timestamp DESC)
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS environment_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            device_id TEXT,
            timestamp TEXT NOT NULL,
            temperature REAL,
            humidity REAL,
            pressure REAL,
            pm1 REAL,
            pm25 REAL,
            pm10 REAL,
            co2 REAL,
            voc REAL,
            iaq REAL,
            source TEXT,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_environment_history_time
        ON environment_history(timestamp DESC)
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sensor_devices (
            device_id TEXT PRIMARY KEY,
            device_type TEXT,
            assigned_user_id TEXT,
            connection TEXT NOT NULL DEFAULT 'OFFLINE',
            last_update TEXT,
            sensor_availability TEXT,
            battery REAL,
            metadata_json TEXT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS thresholds (
            sensor TEXT PRIMARY KEY,
            warning REAL,
            critical REAL,
            minimum REAL,
            maximum REAL,
            unit TEXT,
            updated_at TEXT NOT NULL,
            modified_by TEXT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            sensor TEXT,
            current_value REAL,
            threshold REAL,
            user_id TEXT,
            latitude REAL,
            longitude REAL,
            created_at TEXT NOT NULL,
            resolved_at TEXT,
            status TEXT NOT NULL DEFAULT 'Open'
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin TEXT NOT NULL DEFAULT 'Administrator',
            action TEXT NOT NULL,
            target TEXT,
            timestamp TEXT NOT NULL,
            details TEXT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS recipients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            department TEXT,
            role TEXT,
            email TEXT NOT NULL,
            notification_type TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS communications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            incident_kind TEXT,
            recipient TEXT,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            attachments_json TEXT,
            ai_generated INTEGER NOT NULL DEFAULT 0,
            edited INTEGER NOT NULL DEFAULT 0,
            sent_at TEXT,
            sent_by TEXT,
            status TEXT NOT NULL DEFAULT 'Draft',
            created_at TEXT NOT NULL
        )
        """
    )
    _add_column(conn, "communications", "sent_by TEXT")
    _add_column(conn, "communications", "incident_kind TEXT")

    conn.commit()
    conn.close()


def insert_detection(image_path, source, damage_class, confidence, severity,
                     lat=None, lon=None, description=None, ai_accepted=None,
                     client_ip=None, hazard_type=None,
                     corroboration_area_key=None, authority_area_key=None):
    conn = get_conn()
    cur = conn.execute(
        """
        INSERT INTO detections
            (image_path, source, damage_class, confidence, severity,
             lat, lon, description, ai_accepted, status, created_at,
             client_ip, hazard_type, corroboration_area_key, authority_area_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
        """,
        (
            image_path, source, damage_class, confidence, severity,
            lat, lon, description,
            int(ai_accepted) if ai_accepted is not None else None,
            datetime.now(timezone.utc).isoformat(),
            client_ip, hazard_type or "road_damage",
            corroboration_area_key, authority_area_key,
        ),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def list_by_status(status):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM detections WHERE status = ? ORDER BY created_at DESC", (status,)
    ).fetchall()
    conn.close()
    return rows


def get_detection(detection_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM detections WHERE id = ?", (detection_id,)).fetchone()
    conn.close()
    return row


def update_status(detection_id, status, letter_path=None):
    conn = get_conn()
    conn.execute(
        """
        UPDATE detections
        SET status = ?, reviewed_at = ?, letter_path = COALESCE(?, letter_path)
        WHERE id = ?
        """,
        (status, datetime.now(timezone.utc).isoformat(), letter_path, detection_id),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Track B — authorities (lifecycle pending -> verified, verified -> bounced
# -> pending; a flip, not a new tier)
# ---------------------------------------------------------------------------

def get_or_create_authority(authority_area_key, hazard_type, email):
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM authorities WHERE authority_area_key = ? AND hazard_type = ? AND email = ?",
        (authority_area_key, hazard_type, email),
    ).fetchone()
    if row is None:
        cur = conn.execute(
            """
            INSERT INTO authorities (authority_area_key, hazard_type, email, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (authority_area_key, hazard_type, email, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        authority_id = cur.lastrowid
        conn.close()
        return get_authority(authority_id)
    conn.close()
    return row


def get_authority(authority_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM authorities WHERE id = ?", (authority_id,)).fetchone()
    conn.close()
    return row


def get_verified_authority(authority_area_key, hazard_type):
    conn = get_conn()
    row = conn.execute(
        """
        SELECT * FROM authorities
        WHERE authority_area_key = ? AND hazard_type = ? AND lifecycle = 'verified'
        ORDER BY verified_at ASC LIMIT 1
        """,
        (authority_area_key, hazard_type),
    ).fetchone()
    conn.close()
    return row


def list_authorities():
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM authorities ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return rows


def mark_authority_verified(authority_id):
    conn = get_conn()
    conn.execute(
        """
        UPDATE authorities
        SET lifecycle = 'verified', verified_at = ?, bounced_at = NULL, bounce_reason = NULL
        WHERE id = ?
        """,
        (datetime.now(timezone.utc).isoformat(), authority_id),
    )
    conn.commit()
    conn.close()


def mark_authority_bounced(authority_id, reason=None):
    """verified -> bounced -> pending (flip, so a later verified set re-enables)."""
    conn = get_conn()
    conn.execute(
        """
        UPDATE authorities
        SET lifecycle = 'pending', bounced_at = ?, bounce_reason = ?
        WHERE id = ?
        """,
        (datetime.now(timezone.utc).isoformat(), reason, authority_id),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Track B — corroboration clusters (state only; count is ALWAYS derived from
# detections.client_ip on demand, never stored)
# ---------------------------------------------------------------------------

CLUSTER_WINDOW_STEP = 3600  # 1 h window, sweep step (kept here for config surface)


def get_or_create_cluster(corroboration_area_key, hazard_type, window_start):
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM corroboration_clusters WHERE corroboration_area_key = ? AND hazard_type = ? AND window_start = ?",
        (corroboration_area_key, hazard_type, window_start),
    ).fetchone()
    if row is None:
        conn.execute(
            """
            INSERT INTO corroboration_clusters
                (corroboration_area_key, hazard_type, window_start, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (corroboration_area_key, hazard_type, window_start,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        conn.close()
        return get_cluster_by_window(corroboration_area_key, hazard_type, window_start)
    conn.close()
    return row


def get_cluster_by_window(corroboration_area_key, hazard_type, window_start):
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM corroboration_clusters WHERE corroboration_area_key = ? AND hazard_type = ? AND window_start = ?",
        (corroboration_area_key, hazard_type, window_start),
    ).fetchone()
    conn.close()
    return row


def list_clusters():
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM corroboration_clusters ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return rows


def update_cluster(cluster_id, lifecycle=None, letter_path=None, emailed_at=None):
    conn = get_conn()
    if lifecycle is not None:
        conn.execute(
            "UPDATE corroboration_clusters SET lifecycle = ? WHERE id = ?",
            (lifecycle, cluster_id),
        )
    if letter_path is not None:
        conn.execute(
            "UPDATE corroboration_clusters SET letter_path = ? WHERE id = ?",
            (letter_path, cluster_id),
        )
    if emailed_at is not None:
        conn.execute(
            "UPDATE corroboration_clusters SET emailed_at = ? WHERE id = ?",
            (emailed_at, cluster_id),
        )
    conn.commit()
    conn.close()


def corroboration_count(conn, corroboration_area_key, hazard_type, window_start, window_end):
    """ALWAYS derived: COUNT(DISTINCT client_ip) in the fine area+hazard window."""
    return conn.execute(
        """
        SELECT COUNT(DISTINCT client_ip)
        FROM detections
        WHERE corroboration_area_key = ?
          AND hazard_type = ?
          AND client_ip IS NOT NULL
          AND created_at >= ? AND created_at < ?
        """,
        (corroboration_area_key, hazard_type, window_start, window_end),
    ).fetchone()[0]

def create_complaint(user_id, user_name, email, subject, description, priority, attachment_path=None,
                     category=None, incident_latitude=None, incident_longitude=None,
                     incident_accuracy=None, incident_gps_time=None,
                     environment_snapshot=None):
    """Create a user help-desk complaint and return the stored row."""
    import secrets, json
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    ticket_id = None
    for _ in range(10):
        candidate = f"SS-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
        try:
            cur = conn.execute(
                """
                INSERT INTO complaints
                    (ticket_id, user_id, user_name, email, subject, description, priority,
                     attachment_path, status, created_at, updated_at, category,
                     incident_latitude, incident_longitude, incident_accuracy, incident_gps_time,
                     environment_snapshot_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (candidate, user_id, user_name, email, subject, description, priority,
                 attachment_path, now, now, category, incident_latitude, incident_longitude,
                 incident_accuracy, incident_gps_time, json.dumps(environment_snapshot or {}, ensure_ascii=False)),
            )
            conn.commit()
            ticket_id = cur.lastrowid
            break
        except sqlite3.IntegrityError:
            continue
    if ticket_id is None:
        conn.close()
        raise RuntimeError("Unable to create a unique complaint ticket.")
    row = conn.execute("SELECT * FROM complaints WHERE id = ?", (ticket_id,)).fetchone()
    conn.close()
    return row


def list_complaints_for_user(user_id):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM complaints WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()
    conn.close()
    return rows


def list_complaints():
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM complaints ORDER BY CASE priority WHEN 'Urgent' THEN 0 WHEN 'Intermediate' THEN 1 ELSE 2 END, created_at DESC"
    ).fetchall()
    conn.close()
    return rows


def update_complaint(complaint_id, status, admin_reply=None, priority=None):
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    if priority is None:
        conn.execute(
            """
            UPDATE complaints
            SET status = ?, admin_reply = COALESCE(?, admin_reply), updated_at = ?
            WHERE id = ?
            """,
            (status, admin_reply, now, complaint_id),
        )
    else:
        conn.execute(
            """
            UPDATE complaints
            SET status = ?, priority = ?, admin_reply = COALESCE(?, admin_reply), updated_at = ?
            WHERE id = ?
            """,
            (status, priority, admin_reply, now, complaint_id),
        )
    conn.commit()
    row = conn.execute("SELECT * FROM complaints WHERE id = ?", (complaint_id,)).fetchone()
    conn.close()
    return row



def verify_complaint(complaint_id, action, notes=None, admin="Administrator"):
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    if action == "verify":
        status = "In Progress"
        verified_by = admin
        verified_at = now
    elif action == "reject":
        status = "Closed"
        verified_by = admin
        verified_at = now
    elif action == "resolve":
        status = "Resolved"
        verified_by = admin
        verified_at = now
    elif action == "escalate":
        status = "In Progress"
        verified_by = admin
        verified_at = now
    else:
        conn.close()
        raise ValueError("Unsupported incident action.")
    conn.execute(
        """
        UPDATE complaints
        SET status=?, verified_by=?, verified_at=?, verification_notes=?, updated_at=?
        WHERE id=?
        """,
        (status, verified_by, verified_at, notes, now, complaint_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM complaints WHERE id=?", (complaint_id,)).fetchone()
    conn.close()
    return row

def get_complaint(complaint_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM complaints WHERE id = ?", (complaint_id,)).fetchone()
    conn.close()
    return row



# ---------------------------------------------------------------------------
# Admin control-center persistence helpers
# ---------------------------------------------------------------------------

def upsert_user(user_id, name=None, email=None, phone=None, department=None,
                role="user", status="Idle", account_status="Enabled",
                device_id=None):
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO users
          (user_id, name, email, phone, department, role, status, account_status, device_id, created_at, last_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          name=COALESCE(excluded.name, users.name),
          email=COALESCE(excluded.email, users.email),
          phone=COALESCE(excluded.phone, users.phone),
          department=COALESCE(excluded.department, users.department),
          role=COALESCE(excluded.role, users.role),
          status=COALESCE(excluded.status, users.status),
          account_status=COALESCE(excluded.account_status, users.account_status),
          device_id=COALESCE(excluded.device_id, users.device_id),
          last_active=COALESCE(excluded.last_active, users.last_active)
        """,
        (user_id, name, email, phone, department, role, status, account_status, device_id, now, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    return row

def list_users():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM users ORDER BY COALESCE(last_active, created_at) DESC").fetchall()
    conn.close()
    return rows

def get_user(user_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    return row

def update_user_account(user_id, status=None, account_status=None, role=None,
                        phone=None, department=None):
    conn = get_conn()
    fields, values = [], []
    for col, val in [
        ("status", status), ("account_status", account_status),
        ("role", role), ("phone", phone), ("department", department)
    ]:
        if val is not None:
            fields.append(f"{col} = ?")
            values.append(val)
    if not fields:
        conn.close()
        return get_user(user_id)
    values.append(user_id)
    conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE user_id = ?", values)
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    return row

def insert_user_location(user_id, latitude, longitude, accuracy=None, timestamp=None, status="working"):
    conn = get_conn()
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO user_locations(user_id, latitude, longitude, accuracy, timestamp, status)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, float(latitude), float(longitude), float(accuracy) if accuracy is not None else None, ts, status),
    )
    conn.execute(
        "UPDATE users SET status = ?, last_active = ? WHERE user_id = ?",
        (status, ts, user_id),
    )
    conn.commit()
    row = conn.execute(
        """
        SELECT ul.*, u.name, u.email, u.role, u.department, u.device_id, u.account_status
        FROM user_locations ul
        JOIN users u ON u.user_id = ul.user_id
        WHERE ul.id = ?
        """, (conn.execute("SELECT last_insert_rowid()").fetchone()[0],)
    ).fetchone()
    conn.close()
    return row

def list_latest_user_locations(stale_seconds=120):
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT u.user_id, u.name, u.email, u.role, u.department, u.status, u.account_status,
               u.device_id,
               ul.latitude, ul.longitude, ul.accuracy, ul.timestamp
        FROM users u
        LEFT JOIN user_locations ul
          ON ul.id = (
             SELECT ul2.id FROM user_locations ul2
             WHERE ul2.user_id = u.user_id
             ORDER BY ul2.timestamp DESC, ul2.id DESC LIMIT 1
          )
        ORDER BY u.name COLLATE NOCASE
        """
    ).fetchall()
    conn.close()
    return rows

def list_user_location_history(user_id=None, start=None, end=None, limit=500):
    conn = get_conn()
    sql = """
        SELECT user_id, latitude, longitude, accuracy, timestamp, status
        FROM user_locations
    """
    params = []
    clauses = []
    if user_id:
        clauses.append("user_id = ?")
        params.append(user_id)
    if start:
        clauses.append("timestamp >= ?")
        params.append(start)
    if end:
        clauses.append("timestamp < ?")
        params.append(end)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows

def record_environment(reading, user_id=None, device_id=None, source="firebase"):
    conn = get_conn()
    ts = reading.get("timestamp") or datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO environment_history(
          user_id, device_id, timestamp, temperature, humidity, pressure,
          pm1, pm25, pm10, co2, voc, iaq, source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id, device_id, ts, reading.get("temperature"), reading.get("humidity"),
            reading.get("pressure"), reading.get("pm1"), reading.get("pm25"), reading.get("pm10"),
            reading.get("co2"), reading.get("voc"), reading.get("iaq"), source
        ),
    )
    conn.commit()
    conn.close()

def get_latest_environment_for_user(user_id):
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM environment_history WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1",
        (user_id,),
    ).fetchone()
    conn.close()
    return row

def list_environment_history(start=None, end=None, limit=500):
    conn = get_conn()
    sql = "SELECT * FROM environment_history WHERE 1=1"
    params = []
    if start:
        sql += " AND timestamp >= ?"
        params.append(start)
    if end:
        sql += " AND timestamp < ?"
        params.append(end)
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows

def upsert_sensor_device(device_id, device_type=None, assigned_user_id=None,
                         connection="OFFLINE", last_update=None,
                         sensor_availability=None, battery=None, metadata=None):
    import json
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO sensor_devices(device_id, device_type, assigned_user_id, connection,
                                    last_update, sensor_availability, battery, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
          device_type=COALESCE(excluded.device_type, sensor_devices.device_type),
          assigned_user_id=COALESCE(excluded.assigned_user_id, sensor_devices.assigned_user_id),
          connection=COALESCE(excluded.connection, sensor_devices.connection),
          last_update=COALESCE(excluded.last_update, sensor_devices.last_update),
          sensor_availability=COALESCE(excluded.sensor_availability, sensor_devices.sensor_availability),
          battery=COALESCE(excluded.battery, sensor_devices.battery),
          metadata_json=COALESCE(excluded.metadata_json, sensor_devices.metadata_json)
        """,
        (device_id, device_type, assigned_user_id, connection, last_update,
         sensor_availability, battery, json.dumps(metadata or {}, ensure_ascii=False)),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM sensor_devices WHERE device_id = ?", (device_id,)).fetchone()
    conn.close()
    return row

def list_sensor_devices():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM sensor_devices ORDER BY last_update DESC").fetchall()
    conn.close()
    return rows

def seed_default_thresholds():
    defaults = [
        ("PM1.0", 20, 40, None, None, "µg/m³"),
        ("PM2.5", 35, 55, None, None, "µg/m³"),
        ("PM10", 80, 150, None, None, "µg/m³"),
        ("CO2", 1000, 2000, None, None, "ppm"),
        ("VOC", 1.0, 2.0, None, None, "ppm"),
        ("IAQ", 100, 200, None, None, "index"),
        ("Temperature", None, None, 18, 32, "°C"),
        ("Humidity", None, None, 30, 70, "%"),
    ]
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    for row in defaults:
        conn.execute(
            """
            INSERT INTO thresholds(sensor, warning, critical, minimum, maximum, unit, updated_at, modified_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sensor) DO NOTHING
            """,
            (*row, now, "System Defaults"),
        )
    conn.commit()
    conn.close()

def list_thresholds():
    seed_default_thresholds()
    conn = get_conn()
    rows = conn.execute("SELECT * FROM thresholds ORDER BY sensor").fetchall()
    conn.close()
    return rows

def update_thresholds(items, modified_by="Administrator"):
    supported_units = {
        "PM1.0": "µg/m³", "PM2.5": "µg/m³", "PM10": "µg/m³",
        "CO2": "ppm", "VOC": "ppm", "IAQ": "index",
        "Temperature": "°C", "Humidity": "%",
    }
    normalized = []
    seen = set()
    for item in items or []:
        sensor = str(item.get("sensor") or "").strip()
        if sensor not in supported_units:
            raise ValueError(f"Unsupported threshold sensor: {sensor or 'missing'}")
        if sensor in seen:
            raise ValueError(f"Duplicate threshold sensor: {sensor}")
        seen.add(sensor)

        values = {}
        for field in ("warning", "critical", "minimum", "maximum"):
            raw = item.get(field)
            if raw is None or raw == "":
                values[field] = None
                continue
            try:
                value = float(raw)
            except (TypeError, ValueError):
                raise ValueError(f"{sensor} {field} must be numeric or blank")
            if not math.isfinite(value):
                raise ValueError(f"{sensor} {field} must be finite")
            values[field] = value

        if values["warning"] is not None and values["critical"] is not None and values["warning"] > values["critical"]:
            raise ValueError(f"{sensor} warning cannot exceed critical")
        if values["minimum"] is not None and values["maximum"] is not None and values["minimum"] > values["maximum"]:
            raise ValueError(f"{sensor} minimum cannot exceed maximum")

        normalized.append({
            "sensor": sensor,
            **values,
            "unit": str(item.get("unit") or supported_units[sensor]),
        })

    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    for item in normalized:
        conn.execute(
            """
            INSERT INTO thresholds(sensor, warning, critical, minimum, maximum, unit, updated_at, modified_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sensor) DO UPDATE SET
              warning=excluded.warning, critical=excluded.critical,
              minimum=excluded.minimum, maximum=excluded.maximum,
              unit=excluded.unit, updated_at=excluded.updated_at,
              modified_by=excluded.modified_by
            """,
            (item.get("sensor"), item.get("warning"), item.get("critical"),
             item.get("minimum"), item.get("maximum"), item.get("unit") or "", now, modified_by),
        )
    conn.commit()
    rows = conn.execute("SELECT * FROM thresholds ORDER BY sensor").fetchall()
    conn.close()
    return rows

def resolve_open_alerts_for_sensor(sensor):
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE alerts SET status='Resolved', resolved_at=? WHERE sensor=? AND status='Open'",
        (now, sensor),
    )
    conn.commit()
    conn.close()

def create_alert(alert_type, severity, title, message, sensor=None, current_value=None,
                 threshold=None, user_id=None, latitude=None, longitude=None):
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """
        INSERT INTO alerts(alert_type, severity, title, message, sensor, current_value,
                           threshold, user_id, latitude, longitude, created_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open')
        """,
        (alert_type, severity, title, message, sensor, current_value, threshold,
         user_id, latitude, longitude, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (cur.lastrowid,)).fetchone()
    conn.close()
    return row

def list_alerts(status=None, limit=200):
    conn = get_conn()
    sql = "SELECT * FROM alerts"
    params = []
    if status:
        sql += " WHERE status = ?"
        params.append(status)
    sql += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'URGENT' THEN 1 WHEN 'WARNING' THEN 2 ELSE 3 END, created_at DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows

def resolve_alert(alert_id):
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("UPDATE alerts SET status='Resolved', resolved_at=? WHERE id=?", (now, alert_id))
    conn.commit()
    row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    conn.close()
    return row

def add_admin_activity(action, target=None, details=None, admin="Administrator"):
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO admin_activity(admin, action, target, timestamp, details) VALUES (?, ?, ?, ?, ?)",
        (admin, action, target, now, details),
    )
    conn.commit()
    conn.close()

def list_admin_activity(limit=500):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM admin_activity ORDER BY timestamp DESC LIMIT ?",
        (int(limit),)
    ).fetchall()
    conn.close()
    return rows

def list_recipients():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM recipients ORDER BY created_at DESC").fetchall()
    conn.close()
    return rows

def add_recipient(name, department, role, email, notification_type):
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """
        INSERT INTO recipients(name, department, role, email, notification_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (name, department, role, email, notification_type, now)
    )
    conn.commit()
    row = conn.execute("SELECT * FROM recipients WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.close()
    return row

def delete_recipient(recipient_id):
    conn = get_conn()
    conn.execute("DELETE FROM recipients WHERE id=?", (recipient_id,))
    conn.commit()
    conn.close()

def list_communications(limit=200):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM communications ORDER BY created_at DESC LIMIT ?", (int(limit),)).fetchall()
    conn.close()
    return rows

def add_communication(incident_id, recipient, subject, body, attachments=None,
                      ai_generated=False, edited=False, status="Draft", sent_at=None, sent_by=None, incident_kind=None):
    import json
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """
        INSERT INTO communications(incident_id, incident_kind, recipient, subject, body, attachments_json,
                                    ai_generated, edited, sent_at, sent_by, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (incident_id, incident_kind, recipient, subject, body, json.dumps(attachments or []),
         int(ai_generated), int(edited), sent_at, sent_by, status, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM communications WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.close()
    return row
