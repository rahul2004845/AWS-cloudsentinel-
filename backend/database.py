"""
database.py

CloudSentinel local SQLite storage.

Why this exists:
- Replaces temporary mongomock/in-memory storage.
- Stores all CloudTrail logs and threat alerts permanently in backend/data/cloudsentinel.db.
- Keeps the same collection-like API used by app.py:
    logs_collection.update_one(...)
    logs_collection.find(...).sort(...).limit(...)
    logs_collection.count_documents(...)
    logs_collection.delete_many(...)
    alerts_collection.update_one(...)

No external database server is required.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

SQLITE_PATH = Path(os.getenv("SQLITE_DB_PATH", str(DATA_DIR / "cloudsentinel.db")))
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

_db_lock = threading.RLock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(SQLITE_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


_conn = _connect()


def _init_db() -> None:
    with _db_lock:
        cur = _conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                event_name TEXT,
                event_source TEXT,
                log_type TEXT,
                user_name TEXT,
                user_arn TEXT,
                source_ip TEXT,
                region TEXT,
                threat_detected INTEGER DEFAULT 0,
                severity TEXT,
                doc TEXT NOT NULL
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                event_id TEXT,
                timestamp TEXT,
                threat_name TEXT,
                attack_type TEXT,
                severity TEXT,
                affected_resource TEXT,
                email_status TEXT,
                doc TEXT NOT NULL
            )
            """
        )

        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_event_name ON logs(event_name)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_event_source ON logs(event_source)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_log_type ON logs(log_type)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_region ON logs(region)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_threat ON logs(threat_detected)")

        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_threat_name ON alerts(threat_name)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_email_status ON alerts(email_status)")

        _conn.commit()


_init_db()


def _json_default(value: Any) -> str:
    return str(value)


def _clean_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = dict(doc)
    cleaned.pop("_id", None)
    return cleaned


def _get_nested(doc: Dict[str, Any], key: str, default: Any = None) -> Any:
    if "." not in key:
        return doc.get(key, default)

    current: Any = doc
    for part in key.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(part)
        if current is None:
            return default
    return current


def _matches(doc: Dict[str, Any], query: Optional[Dict[str, Any]]) -> bool:
    if not query:
        return True

    for key, expected in query.items():
        actual = _get_nested(doc, key)

        # basic equality support is enough for this project
        if isinstance(expected, dict):
            if "$in" in expected:
                if actual not in expected["$in"]:
                    return False
            elif "$ne" in expected:
                if actual == expected["$ne"]:
                    return False
            else:
                if actual != expected:
                    return False
        else:
            if actual != expected:
                return False

    return True


class UpdateResult:
    def __init__(self, upserted_id: Optional[str] = None, modified_count: int = 0):
        self.upserted_id = upserted_id
        self.modified_count = modified_count


class SQLiteFindResult:
    def __init__(self, docs: List[Dict[str, Any]]):
        self.docs = docs

    def sort(self, key: str, direction: int = -1) -> "SQLiteFindResult":
        reverse = direction == -1

        def sort_value(doc: Dict[str, Any]) -> Any:
            value = _get_nested(doc, key, "")
            return "" if value is None else value

        self.docs.sort(key=sort_value, reverse=reverse)
        return self

    def limit(self, limit_value: int) -> "SQLiteFindResult":
        self.docs = self.docs[: int(limit_value)]
        return self

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        return iter(self.docs)

    def __len__(self) -> int:
        return len(self.docs)

    def __getitem__(self, item):
        return self.docs[item]


class SQLiteCollection:
    def __init__(self, table: str, primary_key: str):
        self.table = table
        self.primary_key = primary_key

    def create_index(self, *args, **kwargs) -> None:
        # Indexes are created in _init_db().
        return None

    def _row_to_doc(self, row: sqlite3.Row) -> Dict[str, Any]:
        doc = json.loads(row["doc"])
        doc.pop("_id", None)
        return doc

    def _all_docs(self) -> List[Dict[str, Any]]:
        with _db_lock:
            rows = _conn.execute(f"SELECT doc FROM {self.table}").fetchall()
        return [json.loads(row["doc"]) for row in rows]

    def find(
        self,
        query: Optional[Dict[str, Any]] = None,
        projection: Optional[Dict[str, int]] = None,
        *args,
        **kwargs,
    ) -> SQLiteFindResult:
        docs = [doc for doc in self._all_docs() if _matches(doc, query)]

        # Support Mongo-style projection exclusions like {"_id": 0, "raw": 0}
        if projection:
            exclude_keys = [key for key, include in projection.items() if include == 0]
            if exclude_keys:
                projected = []
                for doc in docs:
                    item = dict(doc)
                    for key in exclude_keys:
                        item.pop(key, None)
                    projected.append(item)
                docs = projected

        return SQLiteFindResult(docs)

    def find_one(
        self,
        query: Optional[Dict[str, Any]] = None,
        projection: Optional[Dict[str, int]] = None,
        sort: Optional[List[Tuple[str, int]]] = None,
        *args,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        result = self.find(query=query, projection=projection)
        if sort:
            key, direction = sort[0]
            result.sort(key, direction)
        return result.docs[0] if result.docs else None

    def count_documents(self, query: Optional[Dict[str, Any]] = None, *args, **kwargs) -> int:
        return len([doc for doc in self._all_docs() if _matches(doc, query)])

    def delete_many(self, query: Optional[Dict[str, Any]] = None) -> Dict[str, int]:
        docs_to_keep = []
        deleted = 0

        for doc in self._all_docs():
            if _matches(doc, query):
                deleted += 1
            else:
                docs_to_keep.append(doc)

        with _db_lock:
            _conn.execute(f"DELETE FROM {self.table}")
            for doc in docs_to_keep:
                self._insert_doc(doc)
            _conn.commit()

        return {"deleted_count": deleted}

    def update_one(
        self,
        filter_query: Dict[str, Any],
        update_doc: Dict[str, Any],
        upsert: bool = False,
        *args,
        **kwargs,
    ) -> UpdateResult:
        key_value = filter_query.get(self.primary_key)

        if not key_value:
            # Fallback: use event_id or alert_id if present in update payload.
            candidate = update_doc.get("$setOnInsert") or update_doc.get("$set") or {}
            key_value = candidate.get(self.primary_key)

        if not key_value:
            raise ValueError(f"{self.primary_key} is required for SQLite update_one")

        existing = self.find_one({self.primary_key: key_value})

        if existing:
            set_doc = update_doc.get("$set", {})
            if set_doc:
                updated = dict(existing)
                updated.update(set_doc)
                self._replace_doc(updated)
                return UpdateResult(upserted_id=None, modified_count=1)
            return UpdateResult(upserted_id=None, modified_count=0)

        if upsert:
            insert_doc = update_doc.get("$setOnInsert") or update_doc.get("$set") or {}
            if not insert_doc:
                insert_doc = dict(filter_query)
            insert_doc[self.primary_key] = key_value
            self._insert_doc(insert_doc)
            return UpdateResult(upserted_id=key_value, modified_count=0)

        return UpdateResult(upserted_id=None, modified_count=0)

    def insert_one(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        self._insert_doc(doc)
        return {"inserted_id": doc.get(self.primary_key)}

    def _insert_doc(self, doc: Dict[str, Any]) -> None:
        doc = _clean_doc(doc)
        key_value = str(doc.get(self.primary_key))
        if not key_value or key_value == "None":
            raise ValueError(f"{self.primary_key} missing in document")

        if self.table == "logs":
            params = (
                key_value,
                str(doc.get("timestamp") or doc.get("timestamp_utc") or ""),
                str(doc.get("event_name") or ""),
                str(doc.get("event_source") or ""),
                str(doc.get("log_type") or ""),
                str(doc.get("user_name") or ""),
                str(doc.get("user_arn") or ""),
                str(doc.get("source_ip") or ""),
                str(doc.get("region") or ""),
                1 if doc.get("threat_detected") else 0,
                str(doc.get("max_severity") or doc.get("severity") or ""),
                json.dumps(doc, default=_json_default),
            )
            with _db_lock:
                _conn.execute(
                    """
                    INSERT OR IGNORE INTO logs
                    (event_id, timestamp, event_name, event_source, log_type, user_name, user_arn,
                     source_ip, region, threat_detected, severity, doc)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    params,
                )
                _conn.commit()

        else:
            params = (
                key_value,
                str(doc.get("event_id") or ""),
                str(doc.get("timestamp") or doc.get("timestamp_utc") or ""),
                str(doc.get("threat_name") or ""),
                str(doc.get("attack_type") or ""),
                str(doc.get("severity") or ""),
                str(doc.get("affected_resource") or doc.get("resource_name") or ""),
                str(doc.get("email_status") or ""),
                json.dumps(doc, default=_json_default),
            )
            with _db_lock:
                _conn.execute(
                    """
                    INSERT OR IGNORE INTO alerts
                    (alert_id, event_id, timestamp, threat_name, attack_type, severity,
                     affected_resource, email_status, doc)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    params,
                )
                _conn.commit()

    def _replace_doc(self, doc: Dict[str, Any]) -> None:
        key_value = str(doc.get(self.primary_key))
        with _db_lock:
            _conn.execute(f"DELETE FROM {self.table} WHERE {self.primary_key} = ?", (key_value,))
            _conn.commit()
        self._insert_doc(doc)


class PostgreSQLCollection:
    """PostgreSQL/JSONB implementation of the collection API used by FastAPI.

    PostgreSQL is selected only when DATABASE_URL is configured. This lets local
    contributors use SQLite while production workloads get durable, concurrent
    storage without changing the detection API.
    """
    def __init__(self, table: str, primary_key: str):
        import psycopg
        from psycopg.rows import dict_row
        self.table, self.primary_key, self.psycopg, self.dict_row = table, primary_key, psycopg, dict_row
        self.conninfo = DATABASE_URL
        self._init_schema()

    def _connect(self):
        return self.psycopg.connect(self.conninfo, row_factory=self.dict_row)

    def _init_schema(self):
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS logs (
                event_id TEXT PRIMARY KEY, timestamp TIMESTAMPTZ, event_name TEXT,
                event_source TEXT, log_type TEXT, user_name TEXT, user_arn TEXT,
                source_ip TEXT, region TEXT, account_id TEXT, threat_detected BOOLEAN,
                severity TEXT, doc JSONB NOT NULL)""")
            cur.execute("""CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY, event_id TEXT, timestamp TIMESTAMPTZ,
                threat_name TEXT, attack_type TEXT, severity TEXT, affected_resource TEXT,
                email_status TEXT, doc JSONB NOT NULL)""")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_account_region ON logs(account_id, region)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")

    def _all_docs(self) -> List[Dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT doc FROM {self.table}")
            return [dict(row["doc"]) for row in cur.fetchall()]

    def find(self, query=None, projection=None, *args, **kwargs):
        docs = [doc for doc in self._all_docs() if _matches(doc, query)]
        if projection:
            excluded = [key for key, value in projection.items() if value == 0]
            docs = [{key: value for key, value in doc.items() if key not in excluded} for doc in docs]
        return SQLiteFindResult(docs)

    def find_one(self, query=None, projection=None, sort=None, *args, **kwargs):
        result = self.find(query, projection)
        if sort: result.sort(sort[0][0], sort[0][1])
        return result.docs[0] if result.docs else None

    def count_documents(self, query=None, *args, **kwargs):
        return len([doc for doc in self._all_docs() if _matches(doc, query)])

    def update_one(self, filter_query, update_doc, upsert=False, *args, **kwargs):
        key = filter_query.get(self.primary_key) or (update_doc.get("$setOnInsert") or update_doc.get("$set") or {}).get(self.primary_key)
        if not key: raise ValueError(f"{self.primary_key} is required for PostgreSQL update_one")
        existing = self.find_one({self.primary_key: key})
        if existing:
            changes = update_doc.get("$set", {})
            if not changes: return UpdateResult()
            existing.update(changes); self._upsert(existing)
            return UpdateResult(modified_count=1)
        if not upsert: return UpdateResult()
        doc = dict(update_doc.get("$setOnInsert") or update_doc.get("$set") or filter_query); doc[self.primary_key] = key
        self._upsert(doc)
        return UpdateResult(upserted_id=key)

    def delete_many(self, query=None):
        docs = [doc for doc in self._all_docs() if _matches(doc, query)]
        if not docs: return {"deleted_count": 0}
        with self._connect() as conn, conn.cursor() as cur:
            cur.executemany(f"DELETE FROM {self.table} WHERE {self.primary_key}=%s", [(doc[self.primary_key],) for doc in docs])
        return {"deleted_count": len(docs)}

    def _upsert(self, doc):
        doc = _clean_doc(doc); key = str(doc[self.primary_key])
        if self.table == "logs":
            values = (key, doc.get("timestamp"), doc.get("event_name"), doc.get("event_source"), doc.get("log_type"), doc.get("user_name"), doc.get("user_arn"), doc.get("source_ip"), doc.get("region"), doc.get("account_id"), bool(doc.get("threat_detected")), doc.get("max_severity") or doc.get("severity"), self.psycopg.types.json.Jsonb(doc))
            sql = """INSERT INTO logs(event_id,timestamp,event_name,event_source,log_type,user_name,user_arn,source_ip,region,account_id,threat_detected,severity,doc) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(event_id) DO UPDATE SET timestamp=EXCLUDED.timestamp,event_name=EXCLUDED.event_name,event_source=EXCLUDED.event_source,log_type=EXCLUDED.log_type,user_name=EXCLUDED.user_name,user_arn=EXCLUDED.user_arn,source_ip=EXCLUDED.source_ip,region=EXCLUDED.region,account_id=EXCLUDED.account_id,threat_detected=EXCLUDED.threat_detected,severity=EXCLUDED.severity,doc=EXCLUDED.doc"""
        else:
            values = (key, doc.get("event_id"), doc.get("timestamp"), doc.get("threat_name"), doc.get("attack_type"), doc.get("severity"), doc.get("affected_resource") or doc.get("resource_name"), doc.get("email_status"), self.psycopg.types.json.Jsonb(doc))
            sql = """INSERT INTO alerts(alert_id,event_id,timestamp,threat_name,attack_type,severity,affected_resource,email_status,doc) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(alert_id) DO UPDATE SET event_id=EXCLUDED.event_id,timestamp=EXCLUDED.timestamp,threat_name=EXCLUDED.threat_name,attack_type=EXCLUDED.attack_type,severity=EXCLUDED.severity,affected_resource=EXCLUDED.affected_resource,email_status=EXCLUDED.email_status,doc=EXCLUDED.doc"""
        with self._connect() as conn, conn.cursor() as cur: cur.execute(sql, values)


if DATABASE_URL:
    try:
        logs_collection = PostgreSQLCollection("logs", "event_id")
        alerts_collection = PostgreSQLCollection("alerts", "alert_id")
        DATABASE_MODE = "POSTGRESQL"
    except Exception as exc:
        raise RuntimeError("DATABASE_URL is configured but CloudSentinel could not connect to PostgreSQL") from exc
else:
    logs_collection = SQLiteCollection("logs", "event_id")
    alerts_collection = SQLiteCollection("alerts", "alert_id")
    DATABASE_MODE = "SQLITE_LOCAL"


def database_status() -> Dict[str, Any]:
    try:
        return {
            "mode": DATABASE_MODE,
            "connected": True,
            "using_mock": False,
            "database_path": "PostgreSQL DATABASE_URL" if DATABASE_MODE == "POSTGRESQL" else str(SQLITE_PATH),
            "logs_count": logs_collection.count_documents({}),
            "alerts_count": alerts_collection.count_documents({}),
        }
    except Exception as exc:
        return {
            "mode": DATABASE_MODE,
            "connected": False,
            "using_mock": False,
            "database_path": "PostgreSQL DATABASE_URL" if DATABASE_MODE == "POSTGRESQL" else str(SQLITE_PATH),
            "error": str(exc),
        }
