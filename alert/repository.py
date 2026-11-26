"""Persistent SQLite storage for accepted Alert snapshots, independent of matching.

Each write operation (including apply_changes) is one transaction. Duplicate
insert raises SQLite's IntegrityError; update of an unknown ID raises KeyError.
No implicit upsert, history reset, rule matching or reporting is performed.
"""

from ipaddress import IPv4Address
from collections.abc import Iterable
import json
import math
from pathlib import Path
import sqlite3

from .models import Alert
from .repository_config import RepositoryConfig
from .severity import SEVERITIES


# Decimal TEXT preserves Python's unbounded SID/revision/priority integers.
# Count is a positive SQLite INTEGER (up to 2**63 - 1).
_COLUMN_TYPES = {
    "alert_id": "TEXT", "timestamp": "REAL", "sid": "TEXT", "rev": "TEXT",
    "message": "TEXT", "severity": "TEXT", "src_ip": "TEXT", "src_port": "INTEGER",
    "dst_ip": "TEXT", "dst_port": "INTEGER", "protocol": "TEXT",
    "application_protocol": "TEXT", "flow_id": "TEXT", "first_seen": "REAL",
    "last_seen": "REAL", "priority": "TEXT", "classtype": "TEXT", "count": "INTEGER",
    "match_information": "TEXT",
}
_COLUMNS = tuple(_COLUMN_TYPES)
_SCHEMA_VERSION = 1
_SCHEMA = """
CREATE TABLE alerts (
    alert_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(alert_id)) > 0),
    timestamp REAL NOT NULL CHECK (timestamp >= 0 AND timestamp <= 1.7976931348623157e308),
    sid TEXT NOT NULL CHECK (length(sid) > 0 AND substr(sid,1,1) GLOB '[1-9]'
                            AND sid NOT GLOB '*[^0-9]*'),
    rev TEXT NOT NULL CHECK (length(rev) > 0 AND substr(rev,1,1) GLOB '[1-9]'
                            AND rev NOT GLOB '*[^0-9]*'),
    message TEXT NOT NULL CHECK (length(trim(message)) > 0),
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL CHECK (typeof(src_port) = 'integer' AND src_port BETWEEN 0 AND 65535),
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL CHECK (typeof(dst_port) = 'integer' AND dst_port BETWEEN 0 AND 65535),
    protocol TEXT NOT NULL CHECK (protocol IN ('TCP','UDP')),
    application_protocol TEXT NOT NULL CHECK (application_protocol IN ('HTTP','DNS','SMTP','UNKNOWN')),
    flow_id TEXT,
    first_seen REAL NOT NULL CHECK (first_seen >= 0),
    last_seen REAL NOT NULL CHECK (last_seen >= first_seen AND last_seen <= 1.7976931348623157e308),
    priority TEXT CHECK (priority IS NULL OR (length(priority) > 0
                   AND substr(priority,1,1) GLOB '[1-9]' AND priority NOT GLOB '*[^0-9]*')),
    classtype TEXT,
    count INTEGER NOT NULL CHECK (typeof(count) = 'integer' AND count > 0),
    match_information TEXT NOT NULL,
    CHECK (first_seen <= timestamp AND timestamp <= last_seen)
)
"""
_INDEXES = (
    "CREATE INDEX IF NOT EXISTS alerts_timestamp_idx ON alerts(timestamp, alert_id)",
    "CREATE INDEX IF NOT EXISTS alerts_sid_time_idx ON alerts(sid, timestamp)",
    "CREATE INDEX IF NOT EXISTS alerts_severity_time_idx ON alerts(severity, timestamp)",
    "CREATE INDEX IF NOT EXISTS alerts_src_ip_time_idx ON alerts(src_ip, timestamp)",
    "CREATE INDEX IF NOT EXISTS alerts_dst_ip_time_idx ON alerts(dst_ip, timestamp)",
)


class RepositorySchemaError(RuntimeError):
    """Existing database schema is unsupported; no automatic migration is attempted."""


class RepositoryDataError(ValueError):
    """Stored data cannot be decoded as a valid Alert."""


def _encode(alert: Alert) -> tuple:
    """Validate and serialize a detached snapshot without normalizing away data."""
    if not isinstance(alert, Alert):
        raise TypeError("Expected Alert; policy results and detection dictionaries cannot be stored")
    for name in ("alert_id", "message", "severity", "src_ip", "dst_ip", "protocol", "application_protocol"):
        value = getattr(alert, name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
    if alert.severity not in SEVERITIES:
        raise ValueError("Invalid severity")
    if alert.protocol not in {"TCP", "UDP"} or alert.application_protocol not in {"HTTP", "DNS", "SMTP", "UNKNOWN"}:
        raise ValueError("Unsupported protocol or application_protocol")
    for name in ("src_ip", "dst_ip"):
        value = getattr(alert, name)
        if str(IPv4Address(value)) != value:
            raise ValueError(f"{name} must be normalized IPv4")
    for name in ("flow_id", "classtype"):
        value = getattr(alert, name)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ValueError(f"{name} must be None or a non-empty string")
    for name in ("sid", "rev", "priority", "count", "src_port", "dst_port"):
        value = getattr(alert, name)
        if name == "priority" and value is None:
            continue
        minimum = 0 if name.endswith("_port") else 1
        if type(value) is not int or value < minimum:
            raise ValueError(f"{name} must be an integer >= {minimum}")
        if name.endswith("_port") and value > 65535:
            raise ValueError(f"{name} must be <= 65535")
    if alert.count > 2**63 - 1:
        raise ValueError("count exceeds SQLite's signed 64-bit integer range")
    times = {}
    for name in ("timestamp", "first_seen", "last_seen"):
        value = getattr(alert, name)
        if type(value) not in (int, float):
            raise ValueError(f"{name} must be finite non-negative epoch seconds")
        try:
            value = float(value)
        except OverflowError as exc:
            raise ValueError(f"{name} exceeds the supported numeric range") from exc
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"{name} must be finite non-negative epoch seconds")
        times[name] = value
    if not times["first_seen"] <= times["timestamp"] <= times["last_seen"]:
        raise ValueError("Expected first_seen <= timestamp <= last_seen")
    if type(alert.match_information) is not tuple or any(not isinstance(item, dict) for item in alert.match_information):
        raise ValueError("match_information must be a tuple of JSON-compatible dictionaries")
    try:
        original_evidence = list(alert.match_information)
        evidence = json.dumps(original_evidence, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if json.loads(evidence) != original_evidence:
            raise ValueError("Evidence must round-trip without changing keys or value types")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("match_information must contain lossless, finite JSON metadata") from exc
    record = alert.to_dict()
    record.update(times)
    for name in ("sid", "rev", "priority"):
        if record[name] is not None:
            record[name] = str(record[name])
    record["match_information"] = evidence
    return tuple(record[name] for name in _COLUMNS)


def _decode(row: sqlite3.Row) -> Alert:
    """Reconstruct all fields, including tuple evidence and nullable values."""
    try:
        record = dict(row)
        for name in ("sid", "rev", "priority"):
            if record[name] is not None:
                record[name] = int(record[name])
        evidence = json.loads(record["match_information"])
        if not isinstance(evidence, list):
            raise ValueError("Evidence is not a JSON array")
        record["match_information"] = tuple(evidence)
        alert = Alert(**record)
        _encode(alert)
        return alert
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise RepositoryDataError("Stored row is not a valid Alert") from exc


class AlertRepository:
    """Store/read/update Alert snapshots in a durable local SQLite file.

    Times use UTC Unix epoch seconds (REAL); timestamp remains the event/group
    opening timestamp, distinct from first_seen/last_seen. Evidence is JSON TEXT.
    SID/rev/priority are canonical decimal TEXT on disk and int in the public API.
    Only Alert fields are stored: an AlertGroup's member list is not implicitly
    included in its summary. The persistence adapter writes group summaries.
    Connections are single-threaded. Each write commits before returning.
    """

    def __init__(self, config: RepositoryConfig | None = None) -> None:
        self.config = config if config is not None else RepositoryConfig()
        if not isinstance(self.config, RepositoryConfig):
            raise TypeError("Expected RepositoryConfig")
        self._connection: sqlite3.Connection | None = None
        path = Path(self.config.storage_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(path))
        connection.row_factory = sqlite3.Row
        try:
            self._initialize(connection)
        except BaseException:
            connection.close()
            raise
        self._connection = connection

    @staticmethod
    def _initialize(connection: sqlite3.Connection) -> None:
        """Create a new versioned schema or check an existing one without reset."""
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = ? AND name NOT LIKE ?", ("table", "sqlite_%"))}
            if version == 0 and not tables:
                connection.execute(_SCHEMA)
            elif version != _SCHEMA_VERSION or "alerts" not in tables:
                raise RepositorySchemaError("Unsupported existing database; automatic reset/migration is disabled")
            info = connection.execute("PRAGMA table_info(alerts)").fetchall()
            if ([(row[1], row[2].upper()) for row in info] != list(_COLUMN_TYPES.items())
                    or [row[1] for row in info if row[5]] != ["alert_id"]):
                raise RepositorySchemaError("Existing alerts columns or primary key do not match schema version 1")
            for statement in _INDEXES:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    def _open(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("AlertRepository is closed")
        return self._connection

    def insert(self, alert: Alert) -> None:
        """Insert a new ID; duplicate IDs raise sqlite3.IntegrityError with rollback."""
        self.apply_changes(inserts=(alert,))

    def get_by_id(self, alert_id: str) -> Alert | None:
        """Read a detached Alert, or None for an unknown ID."""
        connection = self._open()
        if not isinstance(alert_id, str) or not alert_id.strip():
            raise ValueError("alert_id must be a non-empty string")
        row = connection.execute(
            f"SELECT {','.join(_COLUMNS)} FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return None if row is None else _decode(row)

    def update(self, alert: Alert) -> None:
        """Replace all fields for an existing ID; unknown IDs raise KeyError.

        No stale-snapshot ordering policy is inferred; callers choose the latest
        summary. This method neither changes IDs nor inserts missing records.
        """
        self.apply_changes(updates=(alert,))

    def apply_changes(
        self, *, inserts: Iterable[Alert] = (), updates: Iterable[Alert] = (),
    ) -> None:
        """Commit inserts and snapshot replacements together, or roll back all.

        Validate every snapshot before SQL. Each ID may occur only once in a
        batch. Repeating the same update in a later call is idempotent: count
        is replaced, never incremented in SQL. Missing updates remain errors.
        """
        connection = self._open()
        new_values = tuple(_encode(alert) for alert in inserts)
        updated_values = tuple(_encode(alert) for alert in updates)
        identifiers = [values[0] for values in new_values + updated_values]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Each alert_id must occur only once in apply_changes")
        with connection:
            for values in new_values:
                connection.execute(
                    f"INSERT INTO alerts ({','.join(_COLUMNS)}) VALUES ({','.join('?' for _ in _COLUMNS)})",
                    values)
            for values in updated_values:
                cursor = connection.execute(
                    f"UPDATE alerts SET {','.join(name + ' = ?' for name in _COLUMNS[1:])} WHERE alert_id = ?",
                    values[1:] + values[:1])
                if cursor.rowcount != 1:
                    raise KeyError(values[0])

    def query(
        self, *, from_time: float | int | None = None, to_time: float | int | None = None,
        severity: str | None = None, sid: int | None = None,
        src_ip: str | None = None, dst_ip: str | None = None,
    ) -> list[Alert]:
        """Read snapshots matching all supplied filters, ordered by timestamp/ID.

        Time is UTC Unix epoch seconds on alerts.timestamp (the opening event),
        NOT last_seen or interval overlap. Bounds are [from_time, to_time);
        omitted bounds are unbounded, equal bounds give [], reversed bounds fail.
        Severity must be canonical uppercase; IPs must be canonical IPv4 strings.
        This method only SELECTs and returns detached Alerts, including open
        snapshots already persisted by the adapter. No reporting is performed.
        """
        connection = self._open()
        bounds = {}
        for name, value in (("from_time", from_time), ("to_time", to_time)):
            if value is None:
                continue
            if type(value) not in (int, float):
                raise ValueError(f"{name} must be finite non-negative epoch seconds or None")
            try:
                number = float(value)
            except OverflowError as exc:
                raise ValueError(f"{name} exceeds the supported numeric range") from exc
            if not math.isfinite(number) or number < 0:
                raise ValueError(f"{name} must be finite non-negative epoch seconds")
            bounds[name] = number
        if "from_time" in bounds and "to_time" in bounds and bounds["from_time"] > bounds["to_time"]:
            raise ValueError("from_time must be <= to_time")
        if severity is not None and (not isinstance(severity, str) or severity not in SEVERITIES):
            raise ValueError("severity must be CRITICAL, HIGH, MEDIUM, LOW or None")
        if sid is not None and (type(sid) is not int or sid < 1):
            raise ValueError("sid must be a positive integer or None")
        for name, value in (("src_ip", src_ip), ("dst_ip", dst_ip)):
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"{name} must be a normalized IPv4 string or None")
                try:
                    if str(IPv4Address(value)) != value:
                        raise ValueError("Not canonical IPv4")
                except ValueError as exc:
                    raise ValueError(f"{name} must be a normalized IPv4 string") from exc
        clauses, parameters = [], []
        for name, operator in (("from_time", ">="), ("to_time", "<")):
            if name in bounds:
                clauses.append(f"timestamp {operator} ?")
                parameters.append(bounds[name])
        for name, value in (("severity", severity), ("sid", str(sid) if sid is not None else None),
                            ("src_ip", src_ip), ("dst_ip", dst_ip)):
            if value is not None:
                clauses.append(f"{name} = ?")
                parameters.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        result = connection.execute(
            f"SELECT {','.join(_COLUMNS)} FROM alerts{where} ORDER BY timestamp ASC, alert_id ASC",
            parameters)
        return [_decode(row) for row in result.fetchall()]

    def close(self) -> None:
        """Release the connection; repeated close is safe."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> "AlertRepository":
        self._open()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
