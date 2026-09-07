#!/usr/bin/env python3
"""End-to-end check for the HTTP client and the SQLite TTL cache.

Both files are plumbing for `modules/deps.py`, and plumbing is where "it looked right" has
already cost this project a session. So the HTTP half runs against a real socket - a
`ThreadingHTTPServer` bound to 127.0.0.1 on an ephemeral port - rather than a mocked
opener: retry counting, gzip decoding, chunked transfers and the size cap all live in the
seam between `urllib` and the wire, which a mock is exactly the wrong tool for reaching.

**No real network is touched, and nothing sleeps for long.** The server is local, the
cache's clock is injected so TTL expiry is instant, and the client's `sleep` is replaced by
a recorder so backoff can be asserted on without waiting for it. The one exception is the
`Retry-After` test, which uses a real 0.2s wait to prove the header reaches the sleeper.

Two behaviours are proved *directly* rather than end-to-end, and say so where they are
checked: the https->http downgrade refusal and the foreign-scheme redirect refusal are
exercised by calling `_GuardedRedirectHandler.redirect_request` with the arguments urllib
would pass it, because standing up a real TLS listener to produce a genuine https->http
redirect needs a certificate this test has no business generating. Everything else -
including that the handler is actually installed in the opener, via the ftp-redirect case -
runs over the socket.

Run:  python3 dev/smoke_httpcache.py
Exit: 0 if every assertion holds, 1 otherwise.
"""

from __future__ import annotations

import gzip
import json
import sys
import tempfile
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codereconwork.core.cache import (  # noqa: E402
    SCHEMA_VERSION,
    CacheEntry,
    TtlCache,
    default_cache_path,
)
from codereconwork.core.context import Config  # noqa: E402
from codereconwork.core.http import (  # noqa: E402
    DEFAULT_MAX_RESPONSE_BYTES,
    Headers,
    HttpClient,
    HttpError,
    InsecureRedirectError,
    JsonError,
    OfflineError,
    ResponseTooLargeError,
    SchemeError,
    TransportError,
    _GuardedRedirectHandler,
    _parse_retry_after,
)

failures: List[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def raises(thunk: Callable[[], Any], expected: type, message: str) -> Optional[BaseException]:
    try:
        thunk()
    except expected as exc:  # type: ignore[misc]
        return exc
    except BaseException as exc:  # noqa: BLE001
        failures.append(f"{message} (raised {type(exc).__name__}: {exc})")
        return None
    failures.append(f"{message} (nothing raised)")
    return None


# --------------------------------------------------------------------------------------
# Test server
# --------------------------------------------------------------------------------------

# Per-path request counters, so "did it retry?" and, more importantly, "did it NOT retry?"
# are answered by what the server saw rather than by what the client says it did.
HITS: Dict[str, int] = {}
HITS_LOCK = threading.Lock()
SEEN: Dict[str, Any] = {}


def hits(path: str) -> int:
    with HITS_LOCK:
        return HITS.get(path, 0)


class Handler(BaseHTTPRequestHandler):
    """Every endpoint the checks below need. Silent: the smoke output is the report."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # noqa: D102 - silence the default logger
        return

    # --- helpers ---------------------------------------------------------------------

    def _count(self) -> int:
        key = self.path.split("?")[0]
        with HITS_LOCK:
            HITS[key] = HITS.get(key, 0) + 1
            return HITS[key]

    def _send(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str = "text/plain",
        extra: Tuple[Tuple[str, str], ...] = (),
        chunked: bool = False,
        lie_about_length: Optional[int] = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for name, value in extra:
            self.send_header(name, value)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(body), 4096):
                piece = body[i : i + 4096]
                self.wfile.write(b"%X\r\n%s\r\n" % (len(piece), piece))
            self.wfile.write(b"0\r\n\r\n")
            return
        declared = len(body) if lie_about_length is None else lie_about_length
        self.send_header("Content-Length", str(declared))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    # --- routes ----------------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        path = self.path.split("?")[0]
        count = self._count()

        if path == "/plain":
            SEEN["plain_headers"] = dict(self.headers.items())
            SEEN["plain_query"] = self.path
            self._send(200, b"hello from the smoke server")

        elif path == "/gzip":
            body = json.dumps({"compressed": True, "filler": "x" * 4000}).encode()
            self._send(
                200,
                gzip.compress(body),
                content_type="application/json",
                extra=(("Content-Encoding", "gzip"),),
            )

        elif path == "/deflate":
            body = b"deflated payload " * 200
            self._send(
                200,
                zlib.compress(body),
                extra=(("Content-Encoding", "deflate"),),
            )

        elif path == "/flaky":
            # 500 twice, then 200. Proves retry happens and that it eventually stops.
            if count < 3:
                self._send(500, b"upstream is having a moment")
            else:
                self._send(200, b"recovered")

        elif path == "/missing":
            self._send(404, b"no such thing")

        elif path == "/bad-request":
            self._send(400, b"you sent nonsense")

        elif path == "/slow-down":
            if count < 2:
                self._send(429, b"slow down", extra=(("Retry-After", "0.2"),))
            else:
                self._send(200, b"thank you")

        elif path == "/come-back-tomorrow":
            self._send(429, b"not today", extra=(("Retry-After", "86400"),))

        elif path == "/huge":
            self._send(200, b"A" * 200_000, chunked=True)

        elif path == "/huge-declared":
            self._send(200, b"A" * 200_000)

        elif path == "/zip-bomb":
            # 5 MB of zeroes compresses to a few KB: the raw cap never trips, so only a
            # cap on decoded bytes can stop this.
            self._send(
                200,
                gzip.compress(b"\0" * (5 * 1024 * 1024)),
                extra=(("Content-Encoding", "gzip"),),
            )

        elif path == "/redirect-ftp":
            self._send(302, b"", extra=(("Location", "ftp://example.invalid/x"),))

        elif path == "/redirect-ok":
            self._send(302, b"", extra=(("Location", "/plain"),))

        elif path == "/not-json":
            self._send(502, b"<html><body>Bad Gateway</body></html>", content_type="text/html")

        elif path == "/repeat-headers":
            self._send(
                200,
                b"ok",
                extra=(("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"), ("X-Case-Test", "yes")),
            )

        elif path == "/latin":
            self._send(
                200,
                "café naïve".encode("iso-8859-1"),
                content_type="text/plain; charset=iso-8859-1",
            )

        else:
            self._send(404, b"unknown route")

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        self._count()
        raw = self._read_body()

        if path == "/echo":
            payload = {
                "received": json.loads(raw.decode()) if raw else None,
                "content_type": self.headers.get("Content-Type"),
                "accept_encoding": self.headers.get("Accept-Encoding"),
                "user_agent": self.headers.get("User-Agent"),
                "method": self.command,
            }
            body = json.dumps(payload).encode()
            self._send(
                200,
                gzip.compress(body),
                content_type="application/json",
                extra=(("Content-Encoding", "gzip"),),
            )

        elif path == "/post-redirect":
            self._send(302, b"", extra=(("Location", "/echo"),))

        else:
            self._send(404, b"unknown route")


class QuietServer(ThreadingHTTPServer):
    """A ThreadingHTTPServer that does not narrate its own expected failures.

    The size-cap checks work by having the client stop reading and hang up mid-response,
    which is precisely the behaviour under test - and which makes the server's default
    `handle_error` dump a `ConnectionResetError` traceback to stderr. Anything else is
    still printed, because a real server-side bug must not be hidden by this.
    """

    def handle_error(self, request: Any, client_address: Any) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


class Server:
    """A local HTTP server on an ephemeral port, for the duration of a `with` block."""

    def __init__(self) -> None:
        self.httpd = QuietServer(("127.0.0.1", 0), Handler)
        self.host, self.port = self.httpd.server_address[0], self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def url(self, path: str) -> str:
        return f"http://{self.host}:{self.port}{path}"

    def __enter__(self) -> "Server":
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class RecordedSleep:
    """Stands in for `time.sleep` so backoff is observable and instant."""

    def __init__(self) -> None:
        self.calls: List[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)

    @property
    def total(self) -> float:
        return sum(self.calls)


# --------------------------------------------------------------------------------------
# HTTP checks
# --------------------------------------------------------------------------------------


def check_http(server: Server) -> None:
    sleeps = RecordedSleep()
    client = HttpClient(Config(timeout=5.0), sleep=sleeps)

    # --- plain 200 GET ----------------------------------------------------------------
    r = client.get(server.url("/plain"), params={"q": "1", "r": "two"})
    check(r.status == 200 and r.ok, f"/plain returned {r.status}")
    check(r.body == b"hello from the smoke server", "/plain body is wrong")
    check(r.text() == "hello from the smoke server", "/plain text() is wrong")
    check(r.attempts == 1, f"a clean 200 took {r.attempts} attempts")
    check(r.method == "GET" and r.url.endswith("q=1&r=two"), f"params were dropped: {r.url}")
    check("q=1" in SEEN.get("plain_query", ""), "the server never saw the query string")
    sent = SEEN.get("plain_headers", {})
    check(sent.get("User-Agent") == Config().user_agent, f"wrong UA: {sent.get('User-Agent')!r}")
    check("gzip" in (sent.get("Accept-Encoding") or ""), "Accept-Encoding was not offered")
    check("Python-urllib" not in json.dumps(sent), "urllib's own User-Agent leaked through")

    # case-insensitive header lookup, on a real response
    check(r.headers.get("CONTENT-TYPE") == "text/plain", "header lookup is case-sensitive")
    check("content-type" in r.headers, "`in` on Headers is case-sensitive")
    rh = client.get(server.url("/repeat-headers"))
    check(rh.headers.get_all("set-cookie") == ["a=1", "b=2"], "repeated headers were lost")
    check(rh.headers.get("x-case-TEST") == "yes", "mixed-case header lookup failed")

    # charset from Content-Type, not a hardcoded utf-8
    latin = client.get(server.url("/latin"))
    check(latin.text() == "café naïve", f"charset ignored: {latin.text()!r}")

    # --- gzip and deflate, decoded transparently --------------------------------------
    gz = client.get(server.url("/gzip"))
    check(gz.headers.get("Content-Encoding") == "gzip", "the server did not send gzip")
    check(gz.json()["compressed"] is True, "gzip body was not decoded")
    check(len(gz.body) > len(gz.headers.get("Content-Length", "0")), "body looks undecoded")

    de = client.get(server.url("/deflate"))
    check(de.body == b"deflated payload " * 200, "deflate body was not decoded")

    # --- POST JSON round trip ----------------------------------------------------------
    payload = {"queries": [{"package": {"name": "flask", "ecosystem": "PyPI"}}], "n": 1}
    pr = client.post_json(server.url("/echo"), payload)
    check(pr.status == 200, f"POST /echo returned {pr.status}")
    echoed = pr.json()
    check(echoed["received"] == payload, "the POST body did not survive the round trip")
    check(echoed["content_type"] == "application/json", "Content-Type was not application/json")
    check(echoed["method"] == "POST", f"the server saw {echoed['method']}, not POST")

    # --- retry on 500, and only until it works -----------------------------------------
    before = len(sleeps.calls)
    flaky = client.get(server.url("/flaky"))
    check(flaky.status == 200 and flaky.body == b"recovered", "the flaky endpoint never recovered")
    check(hits("/flaky") == 3, f"the server saw {hits('/flaky')} requests, expected 3")
    check(flaky.attempts == 3, f"the client reported {flaky.attempts} attempts, expected 3")
    backoffs = sleeps.calls[before:]
    check(len(backoffs) == 2, f"expected 2 backoff sleeps, got {backoffs}")
    check(all(d > 0 for d in backoffs), f"a backoff was not positive: {backoffs}")
    check(len(backoffs) == 2 and backoffs[1] > backoffs[0], f"backoff did not grow: {backoffs}")
    check(len(set(backoffs)) == len(backoffs), "backoff is not jittered")

    # --- NO retry on 4xx ---------------------------------------------------------------
    missing = client.get(server.url("/missing"))
    check(missing.status == 404, f"/missing returned {missing.status}")
    check(hits("/missing") == 1, f"a 404 was retried: the server saw {hits('/missing')} requests")
    check(missing.attempts == 1, f"the client claims {missing.attempts} attempts for a 404")
    bad = client.get(server.url("/bad-request"))
    check(hits("/bad-request") == 1, f"a 400 was retried {hits('/bad-request')} times")
    check(not bad.ok, "a 400 reported ok")
    raises(bad.raise_for_status, HttpError, "raise_for_status did not raise on a 400")
    check(client.get(server.url("/plain")).raise_for_status().ok, "raise_for_status broke a 200")

    # --- Retry-After honoured ----------------------------------------------------------
    # Real sleeping, 0.2s once, because the point is that the header's value reaches the
    # sleeper rather than the jittered backoff schedule.
    timed = HttpClient(Config(timeout=5.0))
    started = time.monotonic()
    slowed = timed.get(server.url("/slow-down"))
    waited = time.monotonic() - started
    check(slowed.status == 200 and slowed.body == b"thank you", "the 429 endpoint never cleared")
    check(hits("/slow-down") == 2, f"expected 2 requests, saw {hits('/slow-down')}")
    check(waited >= 0.2, f"Retry-After: 0.2 was ignored; the retry took {waited:.3f}s")
    check(waited < 2.0, f"Retry-After made us wait {waited:.3f}s, far more than asked")

    # An absurd Retry-After is respected by giving up, not by ignoring it.
    before = len(sleeps.calls)
    tomorrow = client.get(server.url("/come-back-tomorrow"))
    check(tomorrow.status == 429, "the 429 was not returned to the caller")
    check(hits("/come-back-tomorrow") == 1, "we came back sooner than the server asked")
    check(sleeps.calls[before:] == [], f"we slept anyway: {sleeps.calls[before:]}")

    check(_parse_retry_after("120") == 120.0, "numeric Retry-After did not parse")
    check(_parse_retry_after("garbage") is None, "garbage Retry-After should parse to None")
    check(_parse_retry_after(None) is None, "an absent Retry-After should parse to None")
    future = _parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT")
    check(future is not None and future > 0, "an HTTP-date Retry-After did not parse")
    past = _parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT")
    check(past == 0.0, f"a past HTTP-date should clamp to 0, got {past}")

    # --- the size cap -------------------------------------------------------------------
    small = HttpClient(Config(timeout=5.0), max_bytes=1024, sleep=sleeps)
    # Chunked, so there is no Content-Length to short-circuit on: the cap must be enforced
    # from the read loop itself.
    exc = raises(
        lambda: small.get(server.url("/huge")),
        ResponseTooLargeError,
        "a 200 KB chunked response was not capped at 1 KB",
    )
    check(exc is None or "1024" in str(exc), f"the cap error does not name the cap: {exc}")
    # Declared Content-Length over the cap: refused without reading the body.
    raises(
        lambda: small.get(server.url("/huge-declared")),
        ResponseTooLargeError,
        "a declared over-cap Content-Length was not refused",
    )
    # A compression bomb: ~5 KB on the wire, 5 MB decoded. The cap here is deliberately
    # larger than the compressed body, so the declared-Content-Length short-circuit above
    # cannot fire and the *decoded*-byte check is the only thing that can stop it - which
    # is the entire reason decoding is incremental.
    bomber = HttpClient(Config(timeout=5.0), max_bytes=64 * 1024, sleep=sleeps)
    bomb = raises(
        lambda: bomber.get(server.url("/zip-bomb")),
        ResponseTooLargeError,
        "a gzip bomb was not caught by the decoded-byte cap",
    )
    check(bomb is None or "decoding gzip" in str(bomb),
          f"the bomb was not stopped on the decoded side: {bomb}")
    # And the cap does not fire on something that fits.
    check(small.get(server.url("/plain")).ok, "the capped client rejected a small response")
    check(
        DEFAULT_MAX_RESPONSE_BYTES == 8 * 1024 * 1024,
        "the default response cap moved; check it is still deliberate",
    )

    # --- scheme refusals -----------------------------------------------------------------
    for url in ("file:///etc/passwd", "ftp://example.invalid/x", "data:text/plain,hi", "/no-scheme"):
        raises(lambda u=url: client.get(u), SchemeError, f"{url} was not refused")  # type: ignore[misc]
    raises(
        lambda: client.get("http:///no-host"), SchemeError, "a host-less URL was not refused"
    )
    # The refusal is structural, not a string check: no file handler is installed at all.
    installed = {type(h).__name__ for h in client._opener.handlers}
    for forbidden in ("FileHandler", "FTPHandler", "DataHandler", "HTTPCookieProcessor"):
        check(forbidden not in installed, f"{forbidden} is installed in the opener")
    check("_GuardedRedirectHandler" in installed, "the guarded redirect handler is not installed")

    # --- redirects ------------------------------------------------------------------------
    ok_redirect = client.get(server.url("/redirect-ok"))
    check(ok_redirect.status == 200, "a same-scheme redirect was not followed")
    check(ok_redirect.url.endswith("/plain"), f"Response.url is not the final URL: {ok_redirect.url}")

    # End-to-end: a redirect to a foreign scheme, refused by the installed handler.
    raises(
        lambda: client.get(server.url("/redirect-ftp")),
        InsecureRedirectError,
        "a redirect to ftp:// was followed or wrongly typed",
    )
    # End-to-end: a 302 on a POST would silently become a bodyless GET.
    raises(
        lambda: client.post_json(server.url("/post-redirect"), {"a": 1}),
        InsecureRedirectError,
        "a 302 on a POST was not refused",
    )

    check_downgrade_directly()

    # --- offline ----------------------------------------------------------------------------
    offline = HttpClient(Config(offline=True, timeout=5.0))
    before_offline = hits("/plain")
    exc = raises(
        lambda: offline.get(server.url("/plain")),
        OfflineError,
        "an --offline client made a request",
    )
    check(exc is None or "--offline" in str(exc), f"the offline error is unhelpful: {exc}")
    raises(
        lambda: offline.post_json(server.url("/echo"), {"a": 1}),
        OfflineError,
        "an --offline client POSTed",
    )
    check(hits("/plain") == before_offline, "the offline client actually reached the server")
    check(isinstance(OfflineError("x"), HttpError), "OfflineError is not catchable as HttpError")

    # --- transport failure and its retries -----------------------------------------------
    dead = HttpClient(Config(timeout=0.5), sleep=sleeps, retries=2, backoff=0.01)
    before = len(sleeps.calls)
    exc = raises(
        lambda: dead.get("http://127.0.0.1:1/nothing-listens-here"),
        TransportError,
        "a refused connection did not raise TransportError",
    )
    check(getattr(exc, "attempts", 0) == 3, f"expected 3 attempts, got {getattr(exc, 'attempts', 0)}")
    check(len(sleeps.calls) - before == 2, "a connection failure was not retried twice")
    check(dead.stats["failures"] == 1, f"failure was not counted: {dead.stats}")

    # --- json() error quality --------------------------------------------------------------
    html = client.get(server.url("/not-json"))
    exc = raises(html.json, JsonError, "an HTML error page parsed as JSON")
    text = str(exc)
    check("502" in text, "the JSON error does not mention the status")
    check("text/html" in text, "the JSON error does not mention the content type")
    check("Bad Gateway" in text, "the JSON error does not quote the body")
    check(isinstance(exc, HttpError), "JsonError is not catchable as HttpError")

    # --- rate limiting, per host -------------------------------------------------------------
    fake_now = [0.0]
    waits = RecordedSleep()

    def advancing(seconds: float) -> None:
        waits(seconds)
        fake_now[0] += seconds

    limited = HttpClient(
        Config(timeout=5.0, rate_limit=0.75),
        sleep=advancing,
        monotonic=lambda: fake_now[0],
    )
    for _ in range(3):
        limited.get(server.url("/plain"))
    check(len(waits.calls) == 2, f"3 requests to one host produced {len(waits.calls)} waits")
    check(
        all(abs(d - 0.75) < 1e-6 for d in waits.calls),
        f"the rate limit delay is not 0.75s: {waits.calls}",
    )
    check(limited.stats["rate_limit_waits"] == 2, f"waits not counted: {limited.stats}")
    # Per-host, not global. Proved by driving the limiter directly: a genuinely different
    # *host* would mean a second name to resolve, and the obvious candidate (`localhost:1`)
    # spends two seconds failing over from ::1 rather than refusing. The limiter is the
    # only thing under test here, and it is keyed on hostname alone.
    before_waits = len(waits.calls)
    slept = limited._limiter.wait("a-different-host.invalid")
    check(slept == 0.0 and len(waits.calls) == before_waits,
          f"a first request to a different host waited {slept}s on another host's schedule")
    check(limited._limiter.wait("a-different-host.invalid") > 0.0,
          "the second request to that host was not rate limited")

    # --- concurrency: one client, many threads ------------------------------------------------
    results: List[int] = []
    errors: List[str] = []
    lock = threading.Lock()

    def worker() -> None:
        try:
            resp = client.get(server.url("/plain"))
            with lock:
                results.append(resp.status)
        except Exception as exc:  # noqa: BLE001
            with lock:
                errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    check(not errors, f"concurrent GETs raised: {errors[:3]}")
    check(results.count(200) == 8, f"expected 8 concurrent 200s, got {results}")
    check(client.stats["requests"] > 0 and client.stats["bytes_received"] > 0,
          f"stats look wrong: {client.stats}")

    print(f"http:        {client.stats['requests']} requests, {client.stats['retries']} retries, "
          f"{client.stats['bytes_received']} bytes; simulated backoff {sleeps.total:.2f}s")


def check_downgrade_directly() -> None:
    """The https->http refusal, proved by calling the handler the way urllib would.

    Producing a genuine https->http redirect over a socket would mean generating a
    certificate and standing up a TLS listener inside a smoke test, which is a lot of
    machinery to reach one `if`. So this calls `redirect_request` with exactly the
    arguments `http_error_302` passes it - and the ftp-redirect case above already proved,
    end to end, that this handler is the one urllib consults.
    """

    class FakeFp:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    import urllib.request as _urlreq

    handler = _GuardedRedirectHandler()

    def attempt(from_url: str, to_url: str, method: str = "GET") -> Any:
        req = _urlreq.Request(from_url, method=method)
        fp = FakeFp()
        try:
            result = handler.redirect_request(req, fp, 302, "Found", Headers(), to_url)
        except InsecureRedirectError as exc:
            check(fp.closed, f"the refused redirect from {from_url} leaked an open socket")
            return exc
        return result

    downgrade = attempt("https://example.invalid/a", "http://example.invalid/b")
    check(
        isinstance(downgrade, InsecureRedirectError),
        f"https->http was allowed: {downgrade!r}",
    )
    check(
        downgrade is None or "downgrade" in str(downgrade),
        f"the downgrade refusal does not explain itself: {downgrade}",
    )

    foreign = attempt("https://example.invalid/a", "ftp://example.invalid/b")
    check(isinstance(foreign, InsecureRedirectError), "https->ftp was allowed")

    posted = attempt("https://example.invalid/a", "https://example.invalid/b", method="POST")
    check(isinstance(posted, InsecureRedirectError), "a 302 on a POST was allowed")

    upgrade = attempt("http://example.invalid/a", "https://example.invalid/b")
    check(
        isinstance(upgrade, _urlreq.Request),
        f"http->https should be allowed, got {upgrade!r}",
    )
    same = attempt("https://example.invalid/a", "https://example.invalid/b")
    check(isinstance(same, _urlreq.Request), f"https->https should be allowed, got {same!r}")

    # A credential in the URL must not survive into an error message.
    leaky = attempt("https://user:hunter2@example.invalid/a", "http://example.invalid/b")
    check("hunter2" not in str(leaky), "a URL password leaked into a refusal message")


# --------------------------------------------------------------------------------------
# Cache checks
# --------------------------------------------------------------------------------------


def check_cache(tmp: Path) -> None:
    now = [1_000_000.0]  # a plausible epoch, so wall-clock maths is realistic
    clock = lambda: now[0]  # noqa: E731

    path = tmp / "nested" / "dir" / "osv.sqlite"
    cache = TtlCache(path, clock=clock, default_ttl=100.0)
    check(path.exists(), "the cache did not create its parent directories")
    check(not cache.degraded, f"a fresh cache is degraded: {cache.degraded_reason}")

    # --- round trip, including the shapes an OSV response actually has -------------------
    osv_like = {
        "vulns": [{"id": "GHSA-xxxx", "severity": [{"type": "CVSS_V3", "score": "7.5"}]}],
        "unicode": "café",
        "nested": {"a": [1, 2, {"b": None}]},
        "empty": [],
    }
    check(cache.set("flask@2.0.1", osv_like), "set() reported failure")
    check(cache.get("flask@2.0.1") == osv_like, "the value did not round trip")
    check(cache.get("never-stored") is None, "a miss did not return None")
    check(cache.count() == 1, f"expected 1 row, got {cache.count()}")

    # A stored None is distinguishable from a miss, which get() alone cannot do.
    cache.set("known-clean", None)
    check(cache.get("known-clean") is None, "a stored None did not come back as None")
    entry = cache.get_entry("known-clean")
    check(entry is not None and entry.value is None, "get_entry could not represent a stored None")
    check(cache.get_entry("never-stored") is None, "get_entry invented an entry for a miss")

    # --- TTL expiry, via the injected clock, with no sleeping ------------------------------
    cache.set("short", {"v": 1}, ttl=10.0)
    check(cache.get("short") == {"v": 1}, "a fresh entry was not returned")
    now[0] += 9.99
    check(cache.get("short") == {"v": 1}, "an entry expired early")
    now[0] += 0.02  # now 10.01s old, past a 10s TTL
    check(cache.get("short") is None, "an expired entry was served as fresh")

    # --- the explicit stale read path --------------------------------------------------------
    stale = cache.get_stale("short")
    check(stale is not None, "allow_stale did not return the expired entry")
    if stale is not None:
        check(stale.stale is True, "a stale entry was not flagged as stale")
        check(stale.value == {"v": 1}, "the stale entry lost its value")
        check(abs(stale.age - 10.01) < 0.01, f"stale age is {stale.age}, expected ~10.01")
        check(stale.expires_in < 0, f"expires_in should be negative for a stale entry: {stale.expires_in}")
        check(isinstance(stale, CacheEntry), "get_stale returned the wrong type")
    check(cache.get_entry("short", allow_stale=False) is None, "allow_stale=False served a stale row")

    # A zero TTL is stored honestly: already expired, visible only to the stale path.
    cache.set("instant", "x", ttl=0.0)
    check(cache.get("instant") is None, "a zero TTL entry was served as fresh")
    check(cache.get_stale("instant") is not None, "a zero TTL entry was not stored at all")

    # --- namespacing -------------------------------------------------------------------------
    other = TtlCache(path, namespace="ct", clock=clock, default_ttl=100.0)
    other.set("flask@2.0.1", {"different": "consumer"})
    check(cache.get("flask@2.0.1") == osv_like, "another namespace overwrote our key")
    check(other.get("flask@2.0.1") == {"different": "consumer"}, "the second namespace lost its value")
    check(other.count() == 1, f"the ct namespace sees {other.count()} rows, expected 1")
    check(cache.count(all_namespaces=True) >= 5, "all_namespaces did not see across namespaces")

    # --- purge and clear, scoped ---------------------------------------------------------------
    purged = cache.purge_expired()
    check(purged == 2, f"purge_expired removed {purged} rows, expected 2 (short + instant)")
    check(cache.get("flask@2.0.1") == osv_like, "purge_expired removed a live row")
    check(other.count() == 1, "purge_expired reached into another namespace")

    cleared = cache.clear()
    check(cleared == 2, f"clear removed {cleared} rows, expected 2")
    check(cache.count() == 0, "clear left rows behind")
    check(other.count() == 1, "clear emptied another namespace")
    check(other.delete("flask@2.0.1") is True, "delete did not report removing a row")
    check(other.delete("flask@2.0.1") is False, "delete claimed to remove a row twice")

    # --- stats -----------------------------------------------------------------------------------
    stats = cache.stats
    reported = cache.stats.as_dict()  # snapshot for the summary line, before it is poked at
    check(stats.hits >= 5, f"hits look wrong: {stats}")
    check(stats.misses >= 3, f"misses look wrong: {stats}")
    check(stats.stale_hits == 2, f"expected 2 stale hits, got {stats.stale_hits}")
    # Four writes in this namespace: flask, known-clean, short, instant. `other` is a
    # separate instance and keeps its own counters, which is the point of the check below.
    check(stats.writes == 4, f"expected 4 writes, got {stats.writes}")
    check(other.stats.writes == 1, f"the second namespace counted {other.stats.writes} writes")
    check(stats.errors == 0, f"a clean run recorded {stats.errors} cache errors")
    check(stats.lookups == stats.hits + stats.misses + stats.stale_hits, "lookups does not add up")
    check(0.0 <= stats.hit_rate <= 1.0, f"hit_rate out of range: {stats.hit_rate}")
    check("hit_rate" in stats.as_dict(), "as_dict is missing hit_rate")
    stats.hits = 999
    check(cache.stats.hits != 999, "stats returned a live object a caller can corrupt")

    # A non-serialisable value is the caller's bug and must not be swallowed.
    raises(lambda: cache.set("bad", {1, 2, 3}), TypeError, "a set() of a set did not raise TypeError")

    cache.close()
    other.close()
    cache.close()  # idempotent

    # --- persistence across instances -------------------------------------------------------------
    survivor = TtlCache(path, clock=clock, default_ttl=100.0)
    survivor.set("persisted", {"across": "instances"})
    survivor.close()
    reopened = TtlCache(path, clock=clock, default_ttl=100.0)
    check(reopened.get("persisted") == {"across": "instances"}, "the cache did not survive a reopen")
    check(not reopened.degraded, "reopening a healthy cache degraded it")
    reopened.close()

    check_cache_corruption(tmp, clock)
    check_cache_concurrency(tmp)

    # The documented default path, without creating anything in the user's home.
    expected = Path.home() / ".cache" / "codereconwork" / "osv.sqlite"
    check(default_cache_path() == expected, f"default path is {default_cache_path()}, expected {expected}")
    check(SCHEMA_VERSION >= 1, "SCHEMA_VERSION should be a positive integer")

    print(f"cache:       {reported}")


def check_cache_corruption(tmp: Path, clock: Callable[[], float]) -> None:
    """Garbage in the db path, a stranger's schema, and a path that cannot be opened."""
    # 1. Outright garbage: recreated, and usable afterwards.
    garbage = tmp / "corrupt.sqlite"
    garbage.write_bytes(b"this is emphatically not a database\n" * 500)
    cache = TtlCache(garbage, clock=clock, default_ttl=100.0)
    check(not cache.degraded, f"a corrupt file was not recovered: {cache.degraded_reason}")
    check(cache.recreated_reason is not None, "the recreation was not recorded for the report")
    check(cache.set("after-corruption", {"ok": True}), "the recreated cache will not accept writes")
    check(cache.get("after-corruption") == {"ok": True}, "the recreated cache does not read back")
    check(garbage.stat().st_size > 0 and b"emphatically" not in garbage.read_bytes(),
          "the garbage file was not actually replaced")
    cache.close()

    # 2. A file from a future schema version: same treatment, no migration code.
    import sqlite3

    future = tmp / "future.sqlite"
    conn = sqlite3.connect(str(future))
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 99}")
    conn.execute("CREATE TABLE entries (stranger TEXT)")
    conn.commit()
    conn.close()
    newer = TtlCache(future, clock=clock, default_ttl=100.0)
    check(not newer.degraded, f"a future-schema file was not recovered: {newer.degraded_reason}")
    check(newer.set("k", 1) and newer.get("k") == 1, "the recreated future-schema cache does not work")
    newer.close()

    # 3. Unopenable: a directory where the file should be. Nothing here may raise.
    blocked = tmp / "blocked.sqlite"
    blocked.mkdir()
    dead = TtlCache(blocked, clock=clock, default_ttl=100.0)
    check(dead.degraded, "a cache whose path is a directory did not degrade")
    check(dead.degraded_reason and "without a cache" in dead.degraded_reason,
          f"the degraded reason is not report-ready: {dead.degraded_reason}")
    check(dead.set("k", "v") is False, "a degraded cache claimed to have stored something")
    check(dead.get("k") is None, "a degraded cache returned a value")
    check(dead.get_stale("k") is None, "a degraded cache returned a stale value")
    check(dead.purge_expired() == 0 and dead.clear() == 0 and dead.count() == 0,
          "a degraded cache returned non-zero housekeeping counts")
    check(dead.delete("k") is False, "a degraded cache claimed to delete something")
    check(dead.stats.errors >= 1, "the degradation was not counted as an error")
    dead.close()

    # 4. Corruption arriving mid-life is survived by the *caller*, not by luck.
    live = tmp / "mid-life.sqlite"
    cache2 = TtlCache(live, clock=clock, default_ttl=100.0)
    cache2.set("before", 1)
    live.write_bytes(b"clobbered" * 1000)  # under the running connection's feet
    try:
        cache2.get("before")  # may hit the OS page cache and succeed; must never raise
        cache2.set("after", 2)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"clobbering the file mid-run raised {type(exc).__name__}: {exc}")
    cache2.close()


def check_cache_concurrency(tmp: Path) -> None:
    """Eight threads hammering one cache: every write lands, nothing raises."""
    path = tmp / "concurrent.sqlite"
    cache = TtlCache(path, default_ttl=60.0)  # real clock: nothing here depends on time
    errors: List[str] = []
    lock = threading.Lock()
    per_thread = 40

    def worker(n: int) -> None:
        try:
            for i in range(per_thread):
                key = f"t{n}-k{i}"
                cache.set(key, {"thread": n, "i": i})
                got = cache.get(key)
                if got != {"thread": n, "i": i}:
                    with lock:
                        errors.append(f"thread {n} read back {got!r} for {key}")
                cache.get(f"t{(n + 1) % 8}-k{i}")  # cross-thread reads, hits or misses
        except Exception as exc:  # noqa: BLE001
            with lock:
                errors.append(f"thread {n}: {type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    started = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    elapsed = time.monotonic() - started

    check(not errors, f"concurrent cache use failed: {errors[:3]}")
    check(all(not t.is_alive() for t in threads), "a cache worker thread deadlocked")
    expected = 8 * per_thread
    check(cache.count() == expected, f"expected {expected} rows, found {cache.count()}")
    check(cache.stats.writes == expected, f"writes counted {cache.stats.writes}, expected {expected}")
    check(not cache.degraded, f"concurrency degraded the cache: {cache.degraded_reason}")
    check(cache.stats.errors == 0, f"concurrent use logged {cache.stats.errors} errors")
    cache.close()
    print(f"concurrency: {expected} writes + {expected * 2} reads across 8 threads in {elapsed:.2f}s")


# --------------------------------------------------------------------------------------


def main() -> int:
    started = time.monotonic()
    with Server() as server:
        print(f"server:      http://{server.host}:{server.port} (loopback only, no real network)")
        check_http(server)
    with tempfile.TemporaryDirectory() as tmp:
        check_cache(Path(tmp))

    print(f"runtime:     {time.monotonic() - started:.2f}s")
    print()
    if failures:
        for problem in failures:
            print(f"FAIL: {problem}")
        return 1
    print(
        "PASS: gzip/deflate decoded, POST round trip, retries on 5xx/429 with jittered "
        "backoff, no retry on 4xx, Retry-After honoured, size cap enforced mid-read, "
        "non-http(s) and downgrade redirects refused, --offline blocked, per-host rate "
        "limiting; cache round trip, TTL expiry, stale reads, namespacing, corruption "
        "recovery and degradation, 8-thread concurrency, stats"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
