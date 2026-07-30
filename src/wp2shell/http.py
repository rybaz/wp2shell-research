"""TLS-tolerant HTTP transport for the WordPress REST batch endpoint.

The only network primitive the rest of the package needs: POST a batch body to
``/batch/v1`` and return the raw response. HTTPS certificate verification is
disabled so isolated lab targets with self-signed certs work out of the box.
"""

import json
import ssl
import urllib.request
import urllib.error

TIMEOUT = 15

# Isolated labs frequently use self-signed / mismatched certs — tolerate them.
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE

USER_AGENT = "wp2shell/2.0 (authorized-testing)"


def endpoints(base):
    """Both reachable spellings of the batch endpoint (pretty + plain permalinks)."""
    base = base.rstrip("/")
    return [base + "/wp-json/batch/v1", base + "/?rest_route=/batch/v1"]


def send_batch(url, requests_list, cookies=None, nonce=None, validation="normal"):
    """POST a batch/v1 request. Returns ``(status_code, raw_bytes)``.

    ``status_code`` is ``None`` on a transport-level failure (with the error text
    in ``raw_bytes``).
    """
    body = json.dumps({"validation": validation, "requests": requests_list}).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "User-Agent": USER_AGENT}
    if cookies:
        headers["Cookie"] = cookies
    if nonce:
        headers["X-WP-Nonce"] = nonce
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_SSL) as r:
            return r.getcode(), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa: BLE001 - report transport errors to the caller
        return None, str(e).encode()


