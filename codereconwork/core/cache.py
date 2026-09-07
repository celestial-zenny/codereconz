"""A SQLite TTL cache, used first by the dependency scanner to remember OSV.dev answers.

A vulnerability scan asks about the same few hundred packages every run, and OSV's answers
change on the order of once a day. Caching them turns a repeat scan of a big monorepo from
a minute of network round trips into a few milliseconds of local reads, and it is the
difference between a tool people run on every commit and one they run when they remember.

Three properties are load-bearing:

**A cache may never become a failure mode.** It is an optimisation. Every operation here
degrades instead of raising: a corrupt file, a read-only home directory, a full disk, or a
lock held too long all end with "no cached value" and a recorded reason, never with a
traceback that kills a scan the user cares about. The one exception is a value the caller
asked to store that is not JSON-serialisable, which is a bug in the caller and is raised.

**Reading a cache is not network access.** Nothing in this module consults `Config` at
all, and in particular not `Config.offline`. Under `--offline` a scan must still be able to
answer from what it already knows - refusing to read a local file because the user asked
us not to touch the network would be superstition, not safety. `deps.py` is expected to
serve `--offline` runs out of here and note that the answers are cached.

**Expiry is testable without waiting.** The clock is injected, so a test can prove a TTL
boundary in microseconds. A test suite that sleeps is a test suite people stop running.
"""

from __future__ import annotations

import dataclasses
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Bumped when the table layout changes. A file written by a *different* version is treated
# as corrupt and recreated, which is the whole benefit of a cache: no migration code has to
# exist, ever.
SCHEMA_VERSION = 1

DEFAULT_TTL = 24 * 3600.0  # OSV publishes on roughly a daily cadence
DEFAULT_NAMESPACE = "osv"
DEFAULT_BUSY_TIMEOUT = 5.0  # seconds a writer will wait for another writer's commit


def default_cache_path() -> Path:
    """`~/.cache/codereconwork/osv.sqlite`.

    A function rather than a module constant because `Path.home()` raises when neither
    `HOME` nor the password database can answer, and this project is meant to survive
    being dropped onto an odd host. Failing at import time over a *cache* location would
    be absurd; failing when someone actually asks for the default is fine.
    """
    return Path.home() / ".cache" / "codereconwork" / "osv.sqlite"


# --------------------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class CacheEntry:
    """One row, decoded, with the clock reading that was used to judge it.

    `read_at` is carried rather than recomputed on demand so `age` and `expires_in` stay
    consistent with the freshness decision that produced `stale` - and so they honour the
    injected clock instead of quietly reaching for the real one.
    """

    key: str
    value: Any
    created_at: float
    expires_at: float
    read_at: float
    stale: bool = False

    @property
    def age(self) -> float:
        return max(0.0, self.read_at - self.created_at)

    @property
    def expires_in(self) -> float:
        """Negative once expired, which is how much *too old* a stale hit is."""
        return self.expires_at - self.read_at


@dataclass
class CacheStats:
    """Counters worth putting in the report.

    `stale_hits` is separate from `hits` on purpose: a scan that answered from expired
    vulnerability data has told the user something weaker than a fresh answer, and the
    report should be able to say so.
    """

    hits: int = 0
    misses: int = 0
    stale_hits: int = 0
    writes: int = 0
    errors: int = 0

    @property
    def lookups(self) -> int:
        return self.hits + self.misses + self.stale_hits

    @property
    def hit_rate(self) -> float:
        return (self.hits + self.stale_hits) / self.lookups if self.lookups else 0.0

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = dataclasses.asdict(self)
        out["hit_rate"] = round(self.hit_rate, 3)
        return out


# --------------------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------------------

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS entries (
    ns         TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      BLOB NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (ns, key)
) WITHOUT ROWID
"""
# WITHOUT ROWID: this is a pure key/value table with a composite text key, so the implicit
# rowid would be a second B-tree holding a duplicate of every row for nothing.

_CREATE_INDEX = "CREATE INDEX IF NOT EXISTS entries_expires ON entries (expires_at)"

_SELECT = "SELECT value, created_at, expires_at FROM entries WHERE ns = ? AND key = ?"

_UPSERT = (
    "INSERT INTO entries (ns, key, value, created_at, expires_at) VALUES (?, ?, ?, ?, ?) "
    "ON CONFLICT (ns, key) DO UPDATE SET value = excluded.value, "
    "created_at = excluded.created_at, expires_at = excluded.expires_at"
)

_DELETE = "DELETE FROM entries WHERE ns = ? AND key = ?"


class TtlCache:
    """A namespaced, expiring key/value store backed by one SQLite file.

    **Keys are namespaced by column, not by prefix.** Every row carries an `ns`, and an
    instance only ever reads and writes its own. Two consumers sharing the file - the OSV
    lookups and, later, the certificate-transparency subdomain results - cannot collide
    even if they both cache a key called `"example.com"`, and `purge_expired()` or
    `clear()` on one cannot silently empty the other. A prefix scheme would have worked
    too, right up until a key legitimately contained the separator.

    **Values are JSON.** They are stored as a BLOB holding `json.dumps(...)` encoded UTF-8,
    with `sort_keys` for byte-stable rows and the default `ensure_ascii` left on so the
    blob is 7-bit and no exotic character in an upstream API response can produce a row
    SQLite refuses to store. A BLOB rather than TEXT because it round-trips byte-exactly
    regardless of what a future caller does to the connection's `text_factory`.

    **Threading model: one connection per thread, created on first use, all against the
    same file.** `sqlite3` connections are not safe to share between threads and say so by
    default; a single shared connection behind a mutex would also serialise readers for no
    reason, when WAL exists precisely so readers never block. Each connection lives in a
    `threading.local`, so cross-thread use is impossible by construction - which is why
    `check_same_thread=False` is safe here, and it is set only so that `close()` can shut
    down connections its own thread did not create. `close()` therefore has one rule: call
    it after the workers have joined. The stats counters and the degraded flag are plain
    Python state and sit behind a lock.

    **Corruption strategy: recreate once, then fall back to a no-op.** On a
    `sqlite3.DatabaseError` while opening - a truncated file, a half-written file, a file
    from a future schema version - the file (plus its `-wal`/`-shm` siblings) is deleted
    and recreated. That is the right move for a cache and only for a cache: there is
    nothing to preserve, and recreating restores the speedup for this run *and* every
    later run, which an in-memory fallback would not. If recreation also fails - a
    read-only filesystem, a directory sitting where the file should be, no permission -
    the cache disables itself: every read is a miss, every write a no-op, and
    `degraded_reason` holds a sentence fit to hand straight to `ctx.note()`. A scan that
    loses its cache gets slower. It does not get a traceback.
    """

    def __init__(
        self,
        path: Optional[Path] = None,
        *,
        namespace: str = DEFAULT_NAMESPACE,
        default_ttl: float = DEFAULT_TTL,
        clock: Callable[[], float] = time.time,
        busy_timeout: float = DEFAULT_BUSY_TIMEOUT,
    ) -> None:
        if not namespace or not isinstance(namespace, str):
            raise ValueError("a cache namespace must be a non-empty string")
        self.path = Path(path) if path is not None else default_cache_path()
        self.namespace = namespace
        self.default_ttl = float(default_ttl)
        # Wall clock, not monotonic: an expiry has to mean something to the *next* process
        # too, and a monotonic reading is meaningless once this one exits. The price is
        # that a large system clock jump can expire or extend entries early - for a cache,
        # an acceptable price.
        self.clock = clock
        self.busy_timeout = float(busy_timeout)

        self._local = threading.local()
        self._lock = threading.Lock()
        self._connections: List[sqlite3.Connection] = []
        self._stats = CacheStats()
        self._degraded = False
        self._closed = False
        self.degraded_reason: Optional[str] = None
        # Set when the file had to be thrown away, so a caller can note it honestly.
        self.recreated_reason: Optional[str] = None

        # Opened eagerly: a corrupt file should be discovered and dealt with now, while
        # `degraded_reason` can still be reported alongside the other scan notes, rather
        # than halfway through a run when the first lookup happens to land.
        conn = self._bootstrap()
        if conn is not None:
            self._local.conn = conn

    # --- lifecycle ------------------------------------------------------------------

    def _bootstrap(self) -> Optional[sqlite3.Connection]:
        try:
            return self._open()
        except (sqlite3.Error, OSError, ValueError) as first:
            first_reason = _describe(first)

        try:
            self._discard_file()
            conn = self._open()
        except (sqlite3.Error, OSError, ValueError) as second:
            self._degrade(
                f"cache at {self.path} is unusable ({first_reason}) and could not be "
                f"recreated ({_describe(second)}); running without a cache"
            )
            return None

        self.recreated_reason = (
            f"cache at {self.path} was unreadable ({first_reason}) and has been recreated "
            f"empty; this run will refetch everything"
        )
        return conn

    def _open(self) -> sqlite3.Connection:
        """Open, configure and migrate-or-reject one connection to the cache file."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(self.path),
            timeout=self.busy_timeout,
            # Autocommit. Each write is its own transaction, so no thread ever sits on the
            # write lock waiting for a caller to get around to committing.
            isolation_level=None,
            check_same_thread=False,
        )
        try:
            conn.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout * 1000)}")
            # WAL "where available": on a filesystem that cannot do it (some network
            # mounts) SQLite keeps the previous mode and reports it, which is not an error.
            conn.execute("PRAGMA journal_mode = WAL")
            # A cache does not need durability against power loss. The cost of losing the
            # last write is one refetch; the cost of fsyncing every write is every write.
            conn.execute("PRAGMA synchronous = NORMAL")

            row = conn.execute("PRAGMA user_version").fetchone()
            found = int(row[0]) if row else 0
            if found not in (0, SCHEMA_VERSION):
                # Raised, not handled: it routes into the recreate path above, which is
                # the entire migration strategy for a throwaway file.
                raise sqlite3.DatabaseError(
                    f"cache schema version {found}, expected {SCHEMA_VERSION}"
                )
            conn.execute(_CREATE_TABLE)
            conn.execute(_CREATE_INDEX)
            # PRAGMA values cannot be bound as parameters; SCHEMA_VERSION is a module
            # constant int, so there is nothing here for anyone to inject into.
            conn.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")
        except BaseException:
            conn.close()
            raise
        with self._lock:
            self._connections.append(conn)
        return conn

    def _discard_file(self) -> None:
        """Delete the database and its sidecars.

        The `-wal` and `-shm` files matter: leaving a write-ahead log next to a freshly
        created database is a good way to corrupt it a second time.
        """
        for suffix in ("", "-wal", "-shm", "-journal"):
            candidate = Path(str(self.path) + suffix)
            try:
                candidate.unlink()
            except FileNotFoundError:
                continue
            except OSError:
                # A directory in the way, or no permission. `_open` will fail next and the
                # caller degrades; nothing useful to do here.
                continue

    def _conn(self) -> Optional[sqlite3.Connection]:
        """This thread's connection, opening one on first use."""
        if self._closed or self._degraded:
            return None
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn
        try:
            conn = self._open()
        except (sqlite3.Error, OSError) as exc:
            # The file was fine at construction time and is not now. Degrade rather than
            # recreate: another thread may be mid-read, and pulling the file out from
            # under it would turn one thread's problem into everyone's.
            self._degrade(
                f"cache at {self.path} became unusable ({_describe(exc)}); continuing "
                f"without it"
            )
            return None
        self._local.conn = conn
        return conn

    def close(self) -> None:
        """Close every connection this cache opened.

        Safe to call twice. Must be called after worker threads have joined: it reaches
        across threads to close their connections, which is exactly what
        `check_same_thread=False` was enabled for.
        """
        with self._lock:
            self._closed = True
            connections, self._connections = self._connections, []
        for conn in connections:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._local = threading.local()

    def __enter__(self) -> "TtlCache":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- state ----------------------------------------------------------------------

    @property
    def degraded(self) -> bool:
        """True when the cache has given up and is answering every read with a miss."""
        return self._degraded

    @property
    def stats(self) -> CacheStats:
        """A snapshot copy, so a caller cannot accidentally mutate live counters."""
        with self._lock:
            return dataclasses.replace(self._stats)

    def _degrade(self, reason: str) -> None:
        with self._lock:
            if not self._degraded:
                self._degraded = True
                self.degraded_reason = reason
                self._stats.errors += 1

    def _count(self, field: str, amount: int = 1) -> None:
        with self._lock:
            setattr(self._stats, field, getattr(self._stats, field) + amount)

    def _handle_sqlite_error(self, exc: sqlite3.Error, action: str) -> None:
        """Classify a runtime SQLite failure: transient, or the file is gone bad.

        `OperationalError` (database locked, disk full, readonly) is a moment in time and
        the next call may well work, so it is counted and shrugged off.
        `DatabaseError` proper means the file is not a database any more, and continuing to
        query it would just cost every future lookup an exception.
        """
        if isinstance(exc, sqlite3.OperationalError):
            self._count("errors")
            return
        if isinstance(exc, sqlite3.DatabaseError):
            self._degrade(
                f"cache at {self.path} failed during {action} ({_describe(exc)}); "
                f"continuing without it"
            )
            return
        self._count("errors")

    # --- reads ----------------------------------------------------------------------

    def get(self, key: str) -> Optional[Any]:
        """The fresh value for `key`, or None.

        None is returned both for a miss and for a stored `None`. Callers for whom a
        cached `None` is meaningful should use `get_entry`, which distinguishes them.
        """
        entry = self.get_entry(key)
        return entry.value if entry is not None else None

    def get_entry(self, key: str, *, allow_stale: bool = False) -> Optional[CacheEntry]:
        """Look `key` up, optionally accepting an expired row.

        `allow_stale` is opt-in, and deliberately not the default. Yesterday's
        vulnerability data is often better than nothing - if OSV is unreachable, saying
        "here is what we knew this morning" beats reporting no dependencies at all - but a
        security tool that quietly serves expired vulnerability data as if it were current
        is lying. The caller has to ask, and having asked, `entry.stale` and
        `entry.expires_in` give it what it needs to say so in the report.
        """
        conn = self._conn()
        if conn is None:
            self._count("misses")
            return None
        try:
            row: Optional[Tuple[Any, float, float]] = conn.execute(
                _SELECT, (self.namespace, key)
            ).fetchone()
        except sqlite3.Error as exc:
            self._handle_sqlite_error(exc, "a lookup")
            self._count("misses")
            return None

        if row is None:
            self._count("misses")
            return None

        blob, created_at, expires_at = row
        now = self.clock()
        stale = float(expires_at) <= now
        if stale and not allow_stale:
            self._count("misses")
            return None

        try:
            value = _decode(blob)
        except ValueError:
            # A row we cannot decode is worse than no row: it will fail identically every
            # run. Drop it so the next lookup is an honest miss that refetches.
            self._count("errors")
            self._forget(conn, key)
            self._count("misses")
            return None

        self._count("stale_hits" if stale else "hits")
        return CacheEntry(
            key=key,
            value=value,
            created_at=float(created_at),
            expires_at=float(expires_at),
            read_at=now,
            stale=stale,
        )

    def get_stale(self, key: str) -> Optional[CacheEntry]:
        """Explicit shorthand for `get_entry(key, allow_stale=True)`."""
        return self.get_entry(key, allow_stale=True)

    # --- writes ---------------------------------------------------------------------

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """Store `value` under `key`. Returns False if the cache could not take it.

        A value that will not serialise raises `TypeError` from `json.dumps`, unwrapped:
        that is a bug in the caller, and swallowing it would hide the bug while charging
        every future run a refetch for it. A `ttl` of zero or less is stored faithfully as
        an already-expired row, which is only visible through the stale read path.
        """
        blob = _encode(value)
        conn = self._conn()
        if conn is None:
            return False
        now = self.clock()
        expires_at = now + float(self.default_ttl if ttl is None else ttl)
        try:
            conn.execute(_UPSERT, (self.namespace, key, blob, now, expires_at))
        except sqlite3.Error as exc:
            self._handle_sqlite_error(exc, "a write")
            return False
        self._count("writes")
        return True

    def _forget(self, conn: sqlite3.Connection, key: str) -> None:
        try:
            conn.execute(_DELETE, (self.namespace, key))
        except sqlite3.Error:
            pass  # best effort: this is tidying, not the caller's request

    def delete(self, key: str) -> bool:
        """Drop one key. True if a row went away."""
        conn = self._conn()
        if conn is None:
            return False
        try:
            return conn.execute(_DELETE, (self.namespace, key)).rowcount > 0
        except sqlite3.Error as exc:
            self._handle_sqlite_error(exc, "a delete")
            return False

    def purge_expired(self, *, all_namespaces: bool = False) -> int:
        """Delete expired rows and return how many went.

        Scoped to this namespace unless asked otherwise, so housekeeping by one consumer
        never empties another's rows. SQLite reuses the freed pages, so the file stops
        growing without needing a VACUUM - which would want exclusive access to the file
        and is not worth taking mid-scan.
        """
        conn = self._conn()
        if conn is None:
            return 0
        now = self.clock()
        sql = "DELETE FROM entries WHERE expires_at <= ?"
        params: Tuple[Any, ...] = (now,)
        if not all_namespaces:
            sql += " AND ns = ?"
            params = (now, self.namespace)
        try:
            return max(0, conn.execute(sql, params).rowcount)
        except sqlite3.Error as exc:
            self._handle_sqlite_error(exc, "a purge")
            return 0

    def clear(self, *, all_namespaces: bool = False) -> int:
        """Delete every row in this namespace (or all of them) and return the count."""
        conn = self._conn()
        if conn is None:
            return 0
        sql = "DELETE FROM entries"
        params: Tuple[Any, ...] = ()
        if not all_namespaces:
            sql += " WHERE ns = ?"
            params = (self.namespace,)
        try:
            return max(0, conn.execute(sql, params).rowcount)
        except sqlite3.Error as exc:
            self._handle_sqlite_error(exc, "a clear")
            return 0

    def count(self, *, all_namespaces: bool = False) -> int:
        """Rows currently stored, expired ones included."""
        conn = self._conn()
        if conn is None:
            return 0
        sql = "SELECT COUNT(*) FROM entries"
        params: Tuple[Any, ...] = ()
        if not all_namespaces:
            sql += " WHERE ns = ?"
            params = (self.namespace,)
        try:
            row = conn.execute(sql, params).fetchone()
        except sqlite3.Error as exc:
            self._handle_sqlite_error(exc, "a count")
            return 0
        return int(row[0]) if row else 0

    def __repr__(self) -> str:
        state = "degraded" if self._degraded else "ok"
        return f"TtlCache({self.path}, ns={self.namespace!r}, {state})"


# --------------------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------------------


def _encode(value: Any) -> bytes:
    """JSON -> UTF-8 bytes. `sort_keys` makes the stored bytes deterministic."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _decode(blob: Any) -> Any:
    """Bytes -> value, raising `ValueError` for anything that will not parse."""
    if isinstance(blob, str):  # a caller-installed text_factory, or an older row
        return json.loads(blob)
    try:
        return json.loads(bytes(blob).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError(f"cached row is not valid UTF-8: {exc}") from exc


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}".strip().rstrip(":")
