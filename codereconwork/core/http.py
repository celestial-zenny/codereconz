"""A small, deliberately paranoid HTTP client built on `urllib.request`.

Zero dependencies is a project invariant, so there is no `requests` to lean on and the
awkward parts of `urllib` have to be handled here once rather than in every module that
wants to fetch something. The near-term consumer is the dependency scanner posting to
OSV.dev; the live HTTP prober will be the second.

The design is shaped by what a *security* tool must not do:

* **It refuses to run when `--offline` is set.** `ScanModule.unavailable()` already gates
  modules that declare `requires_network`, so this is a second line of defence: a module
  that forgets the declaration, or grows a network call later, still cannot reach the wire.
  Reaching the network under `--offline` is a broken promise, not a warning.
* **TLS verification is not negotiable and there is no switch for it.** `patterns.py`
  ships rules that flag `verify=False` and `CERT_NONE` in other people's code; shipping
  that switch here would be indefensible.
* **The opener is hand-assembled**, not `build_opener()`, because the default handler set
  includes `FileHandler`, `FTPHandler` and `DataHandler`. A scanner has no business
  opening `file:///etc/shadow` no matter what a URL or a redirect says, so those handlers
  are simply never installed and the capability does not exist.
* **A redirect may not downgrade https to http, or change scheme, or convert a POST.**
  `urllib` will happily follow all three. See `_GuardedRedirectHandler`.
* **The response size cap is enforced while reading**, so a hostile or misconfigured
  endpoint cannot exhaust memory before anyone gets a chance to complain. Exceeding it is
  an error; a silently truncated body would be worse than no body at all.
* **No cookie jar is installed**, so nothing a host sets is ever replayed to another host.

This layer is silent: no `print`, no logging, no credentials, and never a request body in
an error message. It returns data and raises `HttpError`; deciding what is worth telling
the user is the calling module's job, via `ctx.note()`.
"""

from __future__ import annotations

import http.client
import json as _json
import random
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
import zlib
from collections.abc import Mapping as _AbcMapping
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple
from urllib.parse import urlencode, urlsplit

from .context import Config

# Not `Config.max_bytes`: that is the walker's per-*file* ceiling and conflating the two
# would mean a `--max-bytes` meant for source files silently resizing network buffers.
DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024

DEFAULT_RETRIES = 3  # additional attempts after the first, so 4 in the worst case
DEFAULT_BACKOFF = 0.5  # seconds, doubled per attempt
MAX_BACKOFF = 8.0
# A server may legitimately ask us to come back in an hour. We will not sit there for an
# hour, and we will not ignore it either - see `_retry_delay`.
MAX_RETRY_AFTER = 30.0

# 429 plus the three 5xx codes that mean "a box in front of the app is unhappy", plus a
# bare 500. 501 and 505 are also 5xx but are permanent configuration answers, and 408 is
# nominally transient but is a 4xx and so excluded on purpose: retrying our own bad
# request only hammers somebody else's API.
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

ALLOWED_SCHEMES = frozenset({"http", "https"})

_CHUNK = 64 * 1024
_ACCEPT_ENCODING = "gzip, deflate"


# --------------------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------------------


class HttpError(Exception):
    """Base for everything this module raises, so one `except` covers the layer."""


class OfflineError(HttpError):
    """A request was attempted while `Config.offline` was set.

    Distinct and catchable on purpose: a module that hits this has a bug worth reporting
    as a skip reason, not a network problem worth retrying.
    """


class SchemeError(HttpError):
    """The URL is not http(s), or has no host."""


class InsecureRedirectError(HttpError):
    """A redirect was refused: scheme downgrade, foreign scheme, or a converted POST."""


class ResponseTooLargeError(HttpError):
    """The response exceeded the size cap. Never a truncation, always an error."""


class TransportError(HttpError):
    """The request could not be completed: DNS, connection, timeout, truncated body.

    Carries `attempts` so a caller can say "gave up after 4 tries" honestly.
    """

    def __init__(self, message: str, *, attempts: int = 1) -> None:
        super().__init__(message)
        self.attempts = attempts


class JsonError(HttpError):
    """A response that was supposed to be JSON was not."""


# --------------------------------------------------------------------------------------
# Headers
# --------------------------------------------------------------------------------------


class Headers(_AbcMapping):
    """Case-insensitive, repeat-aware view of response headers.

    `http.client` already hands back a case-insensitive `email.message.Message`, but that
    is a MIME object with a large mutable API that has no business escaping into module
    code. This is the three operations anyone actually wants, and it copies, so a
    `Response` stays valid after the underlying connection is closed.

    Iteration yields lower-cased canonical names; `raw` preserves what the server sent.
    """

    __slots__ = ("_raw", "_index")

    def __init__(self, items: Iterable[Tuple[str, str]] = ()) -> None:
        self._raw: List[Tuple[str, str]] = [(str(k), str(v)) for k, v in items]
        self._index: Dict[str, List[str]] = {}
        for name, value in self._raw:
            self._index.setdefault(name.lower(), []).append(value)

    @classmethod
    def from_message(cls, message: Any) -> "Headers":
        """Build from an `email.message.Message`, which is what urllib provides."""
        if message is None:
            return cls()
        try:
            return cls(message.items())
        except Exception:  # noqa: BLE001 - a malformed header block is not fatal
            return cls()

    def __getitem__(self, name: str) -> str:
        values = self._index[name.lower()]
        # Comma-joining repeats matches `HTTPResponse.getheader`, which is what callers
        # coming from urllib will expect.
        return values[0] if len(values) == 1 else ", ".join(values)

    def __iter__(self) -> Iterator[str]:
        return iter(self._index)

    def __len__(self) -> int:
        return len(self._index)

    def get_all(self, name: str) -> List[str]:
        """Every value sent for `name`, in order. `Set-Cookie` is the classic repeat."""
        return list(self._index.get(name.lower(), ()))

    @property
    def raw(self) -> List[Tuple[str, str]]:
        return list(self._raw)

    def __repr__(self) -> str:
        return f"Headers({len(self._index)} names)"


def _charset_of(headers: Headers, default: str = "utf-8") -> str:
    """Pull `charset=` out of Content-Type without dragging in the MIME parser."""
    content_type = headers.get("Content-Type", "")
    for part in content_type.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "charset":
            found = value.strip().strip('"').strip("'")
            if found:
                return found
    return default


# --------------------------------------------------------------------------------------
# Response
# --------------------------------------------------------------------------------------


@dataclass
class Response:
    """A completed HTTP exchange, fully read and detached from the socket.

    A non-2xx status is *returned*, not raised: "the server answered 404" is information
    the caller usually wants to branch on, while "we never got an answer" is an exception.
    `raise_for_status()` is there for callers who would rather not branch.
    """

    status: int
    url: str  # final URL, after any redirects we allowed
    headers: Headers
    body: bytes
    method: str = "GET"
    reason: str = ""
    attempts: int = 1
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self, encoding: Optional[str] = None) -> str:
        """Decode the body. Undecodable bytes are replaced rather than raising.

        Same call as `walker.ScanFile.text`: a scanner that dies on one bad byte in a
        third-party response is worse than one that reports slightly mangled text.
        """
        return self.body.decode(encoding or _charset_of(self.headers), errors="replace")

    def json(self) -> Any:
        """Parse the body as JSON, or raise `JsonError` with enough context to debug.

        A bare `JSONDecodeError` reading "Expecting value: line 1 column 1" is useless
        when the real story is "the API returned a 502 HTML error page". So the error
        names the URL, the status and the content type, and quotes a short prefix of the
        *response* (never the request, which may hold anything).
        """
        try:
            return _json.loads(self.body.decode(_charset_of(self.headers)))
        except (ValueError, UnicodeDecodeError) as exc:
            preview = self.body[:120].decode("utf-8", errors="replace").replace("\n", " ")
            if len(self.body) > 120:
                preview += "..."
            raise JsonError(
                f"{self.method} {self.url} returned {self.status} with "
                f"{len(self.body)} bytes of "
                f"{self.headers.get('Content-Type', 'unknown content type')!r} that is not "
                f"JSON ({exc}). Body starts: {preview!r}"
            ) from exc

    def raise_for_status(self) -> "Response":
        """Return self for 2xx, else raise. Chainable: `client.get(u).raise_for_status()`."""
        if self.ok:
            return self
        raise HttpError(
            f"{self.method} {self.url} returned {self.status} {self.reason}".rstrip()
        )


# --------------------------------------------------------------------------------------
# Redirects
# --------------------------------------------------------------------------------------


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuses the three redirects `urllib` would follow that we must not.

    1. **https -> http.** urllib's only redirect scheme check is a hardcoded
       `('http', 'https', 'ftp', '')` allowlist, which happily walks a verified TLS
       connection down onto cleartext. For a tool whose whole point is noticing that
       class of mistake, silently following one is unacceptable.
    2. **A foreign scheme.** `ftp:` passes urllib's allowlist. No FTP handler is even
       installed here, but refusing at the decision point gives a clear error instead of
       a confusing "unknown url type".
    3. **A redirected POST.** For 301/302/303 urllib rewrites a POST into a GET and drops
       the body, per what browsers do. For an API client that is a silent corruption: we
       would receive a confident answer to a question we never asked. 307/308 on a POST
       urllib already refuses, so this only closes the remaining hole.

    Refusals raise `InsecureRedirectError`, which propagates out of `opener.open()`.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        old_scheme = urlsplit(req.full_url).scheme.lower()
        new_scheme = urlsplit(newurl).scheme.lower()
        method = req.get_method()

        refusal: Optional[str] = None
        if new_scheme not in ALLOWED_SCHEMES:
            refusal = f"scheme {new_scheme or '(none)'!r} is not http(s)"
        elif old_scheme == "https" and new_scheme == "http":
            refusal = "it downgrades https to cleartext http"
        elif method not in ("GET", "HEAD"):
            refusal = (
                f"a {code} on a {method} would be replayed as a GET with the body "
                f"dropped, answering a different question than the one asked"
            )

        if refusal is not None:
            # urllib leaves fp open for HTTPError's benefit; we are not raising one, so
            # the socket is ours to close.
            try:
                fp.close()
            except Exception:  # noqa: BLE001
                pass
            raise InsecureRedirectError(
                f"refused the {code} redirect from {_safe_url(req.full_url)} to "
                f"{_safe_url(newurl)}: {refusal}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _safe_url(url: str) -> str:
    """Strip any `user:password@` before a URL goes into an error message."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable url>"
    if not parts.username and not parts.password:
        return url
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    rebuilt = f"{parts.scheme}://{host}{parts.path}"
    return rebuilt + (f"?{parts.query}" if parts.query else "")


# --------------------------------------------------------------------------------------
# Decompression
# --------------------------------------------------------------------------------------


class _Inflater:
    """Incremental gzip/deflate decoder.

    Incremental rather than `gzip.decompress` on the finished body for one reason: the
    size cap has to be checked against *decoded* bytes as they appear. Decompressing
    afterwards would mean a 20 KB response could allocate a gigabyte before anyone looked
    at the total, which is the entire trick behind a compression bomb.

    Also handles the common server bug of labelling a raw DEFLATE stream `deflate` when
    the header says zlib-wrapped: the first chunk is retained until it decodes, so the
    stream can be restarted with raw window bits. Retention is bounded because the caller
    caps raw bytes read.
    """

    __slots__ = ("_obj", "_pending", "_may_retry_raw", "_producing")

    def __init__(self, encoding: str) -> None:
        gzipped = encoding in ("gzip", "x-gzip")
        self._obj = zlib.decompressobj(16 + zlib.MAX_WBITS if gzipped else zlib.MAX_WBITS)
        self._pending = bytearray()
        self._may_retry_raw = not gzipped
        self._producing = False

    def feed(self, chunk: bytes) -> bytes:
        if not self._producing:
            self._pending += chunk
        try:
            out = self._obj.decompress(chunk)
        except zlib.error:
            if self._producing or not self._may_retry_raw:
                raise
            self._obj = zlib.decompressobj(-zlib.MAX_WBITS)
            self._may_retry_raw = False
            out = self._obj.decompress(bytes(self._pending))
        if out:
            self._producing = True
            self._pending = bytearray()
        return out

    def flush(self) -> bytes:
        return self._obj.flush()


# --------------------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------------------


class _RateLimiter:
    """Minimum delay between requests, tracked per host rather than globally.

    Per host because that is where the politeness actually matters: one shared global
    budget would throttle a scan of fifty unrelated hosts to a crawl while still allowing
    a burst against any single one of them if the ordering worked out.

    The reservation is taken under the lock and the sleep happens outside it, so N threads
    aiming at one host queue up at `min_interval` apart instead of all waking together.
    """

    __slots__ = ("_min_interval", "_next", "_lock", "_sleep", "_monotonic")

    def __init__(
        self,
        min_interval: float,
        *,
        sleep: Callable[[float], None],
        monotonic: Callable[[], float],
    ) -> None:
        self._min_interval = max(0.0, min_interval)
        self._next: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._sleep = sleep
        self._monotonic = monotonic

    def wait(self, host: str) -> float:
        """Block until this host may be contacted again. Returns seconds slept."""
        if self._min_interval <= 0.0:
            return 0.0
        with self._lock:
            now = self._monotonic()
            start = max(now, self._next.get(host, 0.0))
            self._next[host] = start + self._min_interval
        delay = start - now
        if delay > 0.0:
            self._sleep(delay)
            return delay
        return 0.0


# --------------------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------------------


@dataclass
class _Target:
    """A validated request destination."""

    url: str
    host: str


class HttpClient:
    """One configured client, safe to share across the engine's worker threads.

    Thread safety comes from having almost no mutable state: the `OpenerDirector` and its
    handlers are configured once and then read-only, `urllib` opens a fresh connection per
    request (it forces `Connection: close`), and redirect bookkeeping is attached to the
    per-call `Request`. The two genuinely shared pieces - the rate limiter's per-host
    schedule and the stats counters - each sit behind a lock. No cookie jar and no auth
    handler are installed, which is what removes the remaining cross-request state.

    `sleep` is injectable for the same reason `TtlCache`'s clock is: a test that proves
    backoff grows should not take eight seconds to do it.
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        *,
        timeout: Optional[float] = None,
        user_agent: Optional[str] = None,
        rate_limit: Optional[float] = None,
        offline: Optional[bool] = None,
        max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        retries: int = DEFAULT_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
        max_backoff: float = MAX_BACKOFF,
        max_retry_after: float = MAX_RETRY_AFTER,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        config = config if config is not None else Config()
        self.config = config
        self.timeout = float(timeout if timeout is not None else config.timeout)
        self.user_agent = user_agent if user_agent is not None else config.user_agent
        self.offline = bool(offline if offline is not None else config.offline)
        self.max_bytes = int(max_bytes)
        self.retries = max(0, int(retries))
        self.backoff = max(0.0, float(backoff))
        self.max_backoff = max(0.0, float(max_backoff))
        self.max_retry_after = max(0.0, float(max_retry_after))
        self._sleep = sleep

        rate = rate_limit if rate_limit is not None else config.rate_limit
        self._limiter = _RateLimiter(float(rate or 0.0), sleep=sleep, monotonic=monotonic)
        self._monotonic = monotonic

        self._stats_lock = threading.Lock()
        self.stats: Dict[str, int] = {
            "requests": 0,
            "retries": 0,
            "failures": 0,
            "bytes_received": 0,
            "rate_limit_waits": 0,
        }

        # A default-verifying context, and no parameter that could weaken it.
        self._ssl_context = ssl.create_default_context()
        self._opener = self._build_opener(self._ssl_context)

    # --- setup ----------------------------------------------------------------------

    @staticmethod
    def _build_opener(context: ssl.SSLContext) -> urllib.request.OpenerDirector:
        """Assemble the opener by hand so unwanted capabilities are simply absent.

        `build_opener()` would add `FileHandler`, `FTPHandler` and `DataHandler`. Not
        installing them means no URL and no redirect can make this client read a local
        file, whatever else goes wrong upstream. `ProxyHandler({})` is explicit rather
        than omitted so an ambient `http_proxy` in the environment cannot silently
        redirect a scan's traffic to a host nobody chose.
        """
        opener = urllib.request.OpenerDirector()
        for handler in (
            urllib.request.ProxyHandler({}),
            urllib.request.UnknownHandler(),
            urllib.request.HTTPHandler(),
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPDefaultErrorHandler(),
            _GuardedRedirectHandler(),
            urllib.request.HTTPErrorProcessor(),
        ):
            opener.add_handler(handler)
        # Drops urllib's own "Python-urllib/3.x" User-Agent; ours is set per request.
        opener.addheaders = []
        return opener

    def _bump(self, key: str, amount: int = 1) -> None:
        with self._stats_lock:
            self.stats[key] = self.stats.get(key, 0) + amount

    # --- public API -----------------------------------------------------------------

    def get(
        self,
        url: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        max_bytes: Optional[int] = None,
    ) -> Response:
        """GET `url`, with `params` appended as a query string if given."""
        if params:
            query = urlencode({k: str(v) for k, v in params.items()})
            url = f"{url}{'&' if urlsplit(url).query else '?'}{query}"
        return self.request(
            "GET", url, headers=headers, timeout=timeout, max_bytes=max_bytes
        )

    def post_json(
        self,
        url: str,
        payload: Any,
        *,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        max_bytes: Optional[int] = None,
    ) -> Response:
        """POST `payload` as JSON.

        A payload that is not JSON-serialisable raises `TypeError` from `json.dumps`
        unchanged: that is the caller's bug, and wrapping it in an `HttpError` would
        disguise a programming error as a network one.
        """
        body = _json.dumps(payload, separators=(",", ":")).encode("utf-8")
        merged: Dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if headers:
            merged.update(headers)
        return self.request(
            "POST", url, body=body, headers=merged, timeout=timeout, max_bytes=max_bytes
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        body: Optional[bytes] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        max_bytes: Optional[int] = None,
    ) -> Response:
        """Perform one logical request, retrying transient failures.

        Returns a `Response` for anything the server answered, including a 4xx or a 5xx
        that outlived our retries - the caller is better placed to decide whether a 404
        from OSV.dev is a problem. Raises `HttpError` only when there is no answer to
        return.
        """
        if self.offline:
            raise OfflineError(
                f"refusing to {method} {_safe_url(url)}: --offline was requested, and "
                f"reaching the network anyway would break that promise"
            )

        target = self._validate(url)
        cap = self.max_bytes if max_bytes is None else int(max_bytes)
        deadline = self.timeout if timeout is None else float(timeout)
        request_headers = self._headers_for(body, headers)

        last: Optional[TransportError] = None
        for attempt in range(1, self.retries + 2):
            if self._limiter.wait(target.host) > 0.0:
                self._bump("rate_limit_waits")
            self._bump("requests")
            started = self._monotonic()
            try:
                response = self._send(
                    method,
                    target,
                    body=body,
                    headers=request_headers,
                    timeout=deadline,
                    max_bytes=cap,
                )
            except TransportError as exc:
                last = TransportError(str(exc), attempts=attempt)
                if attempt > self.retries:
                    self._bump("failures")
                    raise last from exc
                self._backoff_sleep(self._backoff_delay(attempt))
                continue

            response.attempts = attempt
            response.elapsed = self._monotonic() - started
            self._bump("bytes_received", len(response.body))

            if response.status in RETRY_STATUSES and attempt <= self.retries:
                delay = self._retry_delay(response, attempt)
                if delay is None:
                    # The server named a wait longer than we are willing to sit through.
                    # Honouring Retry-After means respecting it or stopping, never
                    # ignoring it and coming straight back.
                    return response
                self._backoff_sleep(delay)
                continue
            return response

        # Unreachable: the loop either returns or raises on its final pass.
        raise last or TransportError(f"{method} {_safe_url(url)} made no attempts")

    # --- internals ------------------------------------------------------------------

    def _validate(self, url: str) -> _Target:
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            raise SchemeError(f"could not parse URL {url!r}: {exc}") from exc
        scheme = parts.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise SchemeError(
                f"refusing {scheme or '(schemeless)'}:// URL {_safe_url(url)}: this "
                f"client speaks http and https only"
            )
        host = (parts.hostname or "").lower()
        if not host:
            raise SchemeError(f"URL {_safe_url(url)} has no host")
        return _Target(url=url, host=host)

    def _headers_for(
        self, body: Optional[bytes], extra: Optional[Mapping[str, str]]
    ) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "User-Agent": self.user_agent,
            "Accept-Encoding": _ACCEPT_ENCODING,
        }
        if body is not None:
            headers.setdefault("Content-Type", "application/octet-stream")
        if extra:
            headers.update(extra)
        return headers

    def _send(
        self,
        method: str,
        target: _Target,
        *,
        body: Optional[bytes],
        headers: Mapping[str, str],
        timeout: float,
        max_bytes: int,
    ) -> Response:
        """One wire attempt. Raises `TransportError` for anything worth retrying."""
        request = urllib.request.Request(
            target.url, data=body, headers=dict(headers), method=method.upper()
        )
        raw: Any
        try:
            raw = self._opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            # An HTTPError *is* a readable response; 404 bodies are often the useful part.
            raw = exc
        except HttpError:
            raise  # our own refusal, surfaced from the redirect handler
        except urllib.error.URLError as exc:
            raise TransportError(
                f"{method} {_safe_url(target.url)} failed: {exc.reason}"
            ) from exc
        except (socket.timeout, TimeoutError) as exc:
            raise TransportError(
                f"{method} {_safe_url(target.url)} timed out after {timeout:g}s"
            ) from exc
        except http.client.HTTPException as exc:
            raise TransportError(
                f"{method} {_safe_url(target.url)}: {type(exc).__name__}: {exc}"
            ) from exc
        except OSError as exc:
            raise TransportError(
                f"{method} {_safe_url(target.url)}: {exc}"
            ) from exc

        response_headers = Headers.from_message(getattr(raw, "headers", None))
        status = int(getattr(raw, "status", 0) or getattr(raw, "code", 0) or 0)
        final_url = str(getattr(raw, "url", None) or target.url)
        reason = str(getattr(raw, "reason", "") or "")
        try:
            payload = self._read_body(
                raw, headers=response_headers, max_bytes=max_bytes, url=final_url
            )
        finally:
            try:
                raw.close()
            except Exception:  # noqa: BLE001 - closing is best effort
                pass

        return Response(
            status=status,
            url=final_url,
            headers=response_headers,
            body=payload,
            method=method.upper(),
            reason=reason,
        )

    def _read_body(
        self, stream: Any, *, headers: Headers, max_bytes: int, url: str
    ) -> bytes:
        """Read and decode the body, checking the cap on every chunk.

        Both the compressed and the decoded totals are checked. Capping the raw side
        bounds how much we will pull off the socket; capping the decoded side is what
        actually stops a compression bomb, since the point of one is that the raw side
        looks harmless.
        """
        encoding = headers.get("Content-Encoding", "").strip().lower()
        inflater = (
            _Inflater(encoding)
            if encoding in ("gzip", "x-gzip", "deflate")
            else None
        )

        # A declared Content-Length over the cap saves reading a byte, but it is a hint
        # only: the enforcement below is what has to be correct, because the header can
        # lie or be absent entirely on a chunked response.
        declared = headers.get("Content-Length")
        if declared and declared.strip().isdigit() and int(declared) > max_bytes:
            raise ResponseTooLargeError(
                f"{_safe_url(url)} declared {int(declared)} bytes, over the "
                f"{max_bytes} byte cap; not reading it"
            )

        out = bytearray()
        raw_total = 0
        try:
            while True:
                chunk = stream.read(_CHUNK)
                if not chunk:
                    break
                raw_total += len(chunk)
                if raw_total > max_bytes:
                    raise ResponseTooLargeError(
                        f"{_safe_url(url)} sent more than the {max_bytes} byte cap "
                        f"(compressed); refusing to keep reading"
                    )
                out += inflater.feed(chunk) if inflater is not None else chunk
                if len(out) > max_bytes:
                    raise ResponseTooLargeError(
                        f"{_safe_url(url)} expanded past the {max_bytes} byte cap"
                        + (f" while decoding {encoding}" if inflater else "")
                    )
            if inflater is not None:
                out += inflater.flush()
                if len(out) > max_bytes:
                    raise ResponseTooLargeError(
                        f"{_safe_url(url)} expanded past the {max_bytes} byte cap "
                        f"while decoding {encoding}"
                    )
        except (socket.timeout, TimeoutError) as exc:
            raise TransportError(
                f"timed out reading the body of {_safe_url(url)}"
            ) from exc
        except zlib.error as exc:
            # A truncated or corrupt compressed body usually means a cut transfer, which
            # is exactly what a retry is for.
            raise TransportError(
                f"could not decode the {encoding} body of {_safe_url(url)}: {exc}"
            ) from exc
        except http.client.HTTPException as exc:
            raise TransportError(
                f"{type(exc).__name__} reading the body of {_safe_url(url)}"
            ) from exc
        except OSError as exc:
            raise TransportError(f"error reading the body of {_safe_url(url)}: {exc}") from exc
        return bytes(out)

    # --- backoff --------------------------------------------------------------------

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff with equal jitter.

        Jitter matters because the engine fires requests from a thread pool: without it,
        every worker that hit the same 503 retries in lockstep and re-creates the spike
        that caused it. Equal jitter (half fixed, half random) keeps the schedule
        monotonic while still spreading the herd.

        `random` is fine here and is not the weak-randomness mistake this project flags
        elsewhere: nothing about a sleep duration is a security value.
        """
        window = min(self.backoff * (2 ** (attempt - 1)), self.max_backoff)
        return window / 2.0 + random.random() * (window / 2.0)

    def _backoff_sleep(self, delay: float) -> None:
        self._bump("retries")
        if delay > 0.0:
            self._sleep(delay)

    def _retry_delay(self, response: Response, attempt: int) -> Optional[float]:
        """How long to wait before retrying, or None to stop retrying.

        None means "the server asked for longer than `max_retry_after`". Coming back
        sooner than asked is how a scanner earns a block, so we stop instead and hand the
        caller the 429 to report.
        """
        asked = _parse_retry_after(response.headers.get("Retry-After"))
        if asked is None:
            return self._backoff_delay(attempt)
        if asked > self.max_retry_after:
            return None
        return max(0.0, asked)


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Seconds from a `Retry-After` header, which may be a count or an HTTP date."""
    if not value:
        return None
    raw = value.strip()
    if raw.isdigit():
        return float(raw)
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
