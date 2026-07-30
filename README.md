# wp2shell — CVE-2026-63030 + CVE-2026-60137 research PoC

A research proof-of-concept for **"wp2shell"**: an **unauthenticated** WordPress
core compromise chain combining a REST batch **handler-permission desync**
(CVE-2026-63030) with a `WP_Query` **SQL injection** (CVE-2026-60137). Chained via
a **nested batch**, an anonymous attacker reads arbitrary database contents —
including administrator password hashes — from a stock install, **no plugins
required**.

> ⚠️ **Authorized security research only.** Read [`AUTHORIZATION.md`](AUTHORIZATION.md)
> before running anything. These tools act on a single explicitly-specified target
> and contain no scanning or mass-exploitation.

## Affected / fixed

| Branch | Vulnerable | Fixed |
|---|---|---|
| 7.0.x | 7.0.0 – 7.0.1 | **7.0.2** |
| 6.9.x | 6.9.0 – 6.9.4 | **6.9.5** |

**Remediation:** update WordPress core to ≥ 7.0.2 / ≥ 6.9.5. The 63030 fix is a
one-line re-alignment in `serve_batch_request_v1()`; the 60137 fix replaces an
`is_array()`-gated `absint` with `wp_parse_id_list()` in `WP_Query`.

## The chain in one paragraph

`serve_batch_request_v1()` builds parallel `$validation` and `$matches` arrays
that desync when a sub-request path fails to parse — so an attacker steers which
handler executes a given request, and that handler's input validation never runs.
The SQLi sink (`author__not_in`, via the `author_exclude` param) lives in the
posts `get_items` **GET** handler, which a single-level batch can't reach. A
**batch-inside-a-batch** defeats that: the outer desync seats
`serve_batch_request_v1` itself on a posts donor (so the inner request array skips
method validation, allowing GET), and the inner desync seats `get_items` with a
raw `author_exclude` string → SQL injection. Full mechanics in
[`docs/analysis.md`](docs/analysis.md).

## Layout

```
wp2shell-research/
├── src/wp2shell/         # the package
│   ├── http.py           # TLS-tolerant batch transport
│   ├── desync.py         # 63030 primitives: detect, probe, seat
│   ├── sqli.py           # 60137 nested-batch UNION/blind extraction
│   └── cli.py            # unified `wp2shell` CLI
├── docs/
│   ├── USAGE.md          # step-by-step usage
│   ├── analysis.md       # full technical analysis + defensive measures
│   └── weaponization-gap.md
├── AUTHORIZATION.md
├── LICENSE               # MIT
└── pyproject.toml
```

## Install

Pure standard library (Python 3.8+), no dependencies.

```bash
# from a clone:
pip install -e .            # provides the `wp2shell` command
# or run without installing:
PYTHONPATH=src python3 -m wp2shell --help
```

## Quickstart

```bash
# 1) Is the target vulnerable? (non-destructive)
wp2shell check http://TARGET/

# 2) Unauthenticated database read via the clean-core chain
wp2shell sqli http://TARGET/
#   @@version    : ...
#   current_user : ...
#   admin_login  : admin
#   admin_hash   : $wp$2y$12$…      <- read with no authentication

# 3) Extract anything
wp2shell sqli http://TARGET/ --expr "SELECT COUNT(*) FROM wp_users"
```

## Commands

**Assessment** — point these at an authorized target:

| Command | Impact | Purpose |
|---|---|---|
| `check` | none | Detector — VULNERABLE / NOT VULNERABLE (exit 1 / 0). |
| `sqli` | DB read | Unauthenticated UNION/blind SQL injection (CVE-2026-60137 via 63030). |

**Research** — raw desync primitives for studying the bug (not scanners):

| Command | Impact | Purpose |
|---|---|---|
| `probe` | none | Confirm the desync via the handler-substitution signal. |
| `seat` | varies | Run an arbitrary target handler via the desync (raw primitive). |

See [`docs/USAGE.md`](docs/USAGE.md) for a full walkthrough, including standing up
a vulnerable lab and verifying the patch closes it.

## Defensive takeaways

1. **Patch core** — the only complete fix.
2. **WAF / virtual patch** — flag `batch/v1` bodies with an unparseable
   sub-request `path`, **nested** `requests` arrays (batch-in-batch), and
   non-integer-array `author_exclude`/`include`/`exclude` values.
3. **Audit plugins/themes** for permissive REST **write** routes whose input
   validation lives only in the args schema — the desync bypasses that validation.

Full detection signatures and mitigations: [`docs/analysis.md`](docs/analysis.md) §5.
