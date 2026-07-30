# wp2shell (CVE-2026-63030) — Weaponization-Gap Analysis

**Purpose:** characterize how far the *confirmed* pre-auth authorization primitive is from a working
unauthenticated RCE, to support a time-to-public-weaponization risk estimate. This is source analysis
against a controlled lab (`TARGET`, WordPress 7.0). Then, build a full working exploit.

**Source of truth:** `wp-includes/rest-api/class-wp-rest-server.php` from the live 7.0 install
(1,980 lines). Relevant methods: `serve_batch_request_v1` (1709), `respond_to_request` (1232),
`match_request_to_handler` (1147). Affected range 6.9.0–6.9.4 / 7.0.0–7.0.1; fixed 6.9.5 / 7.0.2.

---

## 1. The defect (confirmed)

`serve_batch_request_v1` builds three parallel structures over the sub-requests, but they do **not**
stay index-aligned when a sub-request path fails to parse.

**Build phase** — `$requests[]` gets one entry per sub-request; a path that fails `wp_parse_url()`
(e.g. `"http://:"`) becomes a `WP_Error` entry *in place*, preserving index.

**Validation phase** — iterate `$requests`:

```php
foreach ( $requests as $single_request ) {
    if ( is_wp_error( $single_request ) ) {
        $has_error    = true;
        $validation[] = $single_request;   // validation gets a slot
        continue;                          // <-- matches does NOT
    }
    $match     = $this->match_request_to_handler( $single_request );
    $matches[] = $match;                   // matches gets a slot
    ...
    $validation[] = true | $error;         // validation gets a slot
}
```

A malformed sub-request pushes to `$validation` **but not** `$matches`. So `$matches` is indexed by
*valid* requests only, while `$validation` (and `$requests`) are indexed by *all* requests. One leading
malformed request ⇒ **`$matches` is shifted one position ahead of the request index.**

**Execution phase** — iterate `$requests` by `$i` and index `$matches` with that same `$i`:

```php
$match = $matches[ $i ];                    // drifted!
...
list( $route, $handler ) = $match;
$result = $this->respond_to_request( $single_request, $route, $handler, $error );
```

`respond_to_request` then runs **the drifted handler's** `permission_callback` and **the drifted
handler's** `callback`, but passes **the original request** (`$single_request`) as the argument:

```php
$permission = call_user_func( $handler['permission_callback'], $request );   // wrong route's gate
...
$response   = call_user_func( $handler['callback'], $request );              // wrong route's handler
```

### Index trace of the probe (verified live)

| pos | request | `$matches[$i]` (drifted) | `$validation[$i]` | executed by | observed |
|----|----------------------------------|--------------------------|-------------------|-------------------------|-----------------------|
| 0 | `POST "http://:"` (malformed) | — (no slot) | `parse_path_failed` | short-circuit | `400 parse_path_failed` |
| 1 | `DELETE /wp/v2/categories/0` | **block-renderer** handler | `true` | block-renderer gate | **`401 block_cannot_read`** |
| 2 | `POST .../block-renderer/...` | undefined | `rest_batch_not_allowed` | short-circuit (error set) | `400 rest_batch_not_allowed` |

The categories `DELETE` at pos 1 is judged by the **block-renderer's** permission gate — a route it
never addressed. On 7.0.2 the same pos-1 request returns `rest_term_invalid` (its own correct handler).
That single substitution is the whole vulnerability signal.

**Net primitive:** attacker-controlled request *N* is executed against request *N+1*'s route
handler — a request-to-handler substitution driven entirely by unauthenticated input.

---

## 2. What the primitive does and does NOT give you

**Does give (confirmed, low effort):**
- **`allow_batch` allowlist bypass.** The per-slot `allow_batch` gate is checked in *validation* against
  each request's **own** correct match. In execution the **drifted** handler runs. So a handler that is
  *not* batch-enabled (block-renderer) executes anyway, because the gate that passed belonged to the
  batch-enabled request occupying that slot (categories). The "which routes may be batched" control is
  defeated. This is the demonstrated pre-auth authorization-integrity break.

**Does NOT give (by itself):**
- **A free pass on the target route's own permission check.** In `respond_to_request` the executed
  `permission_callback` and `callback` come from the **same** drifted handler. So the drifted-into route
  still runs *its own* gate against the borrowed request. That is exactly why the probe returns
  `block_cannot_read` (denied) rather than executing the block renderer: block-renderer requires
  `edit_posts`, the borrowed request is unauthenticated, gate denies. The authorization is *misrouted*,
  not *removed*.

This is the precise reason the engagement's bounded escalation attempts stalled: seating a
powerful-but-gated handler still hits that handler's own permission callback.

---

## 3. The gap to unauthenticated RCE (the next approved step)

To convert "run handler H against a borrowed request" into unauth code execution, a weaponizer must
line up **all** of:

1. **A batch-enabled donor route** at slot *i* whose `has_valid_params()`/`sanitize_params()` pass with
   no auth, so `$validation[i] === true` (this is what lets the drifted handler execute at all).
2. **A target handler H** at slot *i+1* that is **code-execution-capable or state-changing** through its
   `callback` when fed attacker-controlled params.
3. **H's own `permission_callback` must return truthy for an unauthenticated, attacker-shaped request** —
   because that is the gate that actually runs. This is the hard constraint. It requires either:
   - a route that is genuinely public (permissive gate) *and* whose callback is dangerous — an unusual
     pairing core tries hard to avoid; or
   - a **multi-stage chain**: use a permissive-gate handler first to mutate server state (option write,
     user/nonce creation, cache/transient poisoning) so a *later* sub-request's gate then passes. Because
     gate and callback are coupled per call, separating "who authorizes" from "what executes" is only
     achievable *across* sub-requests, i.e. by chaining state changes.

Item 3 is what the Hadrian writeup withholds and what was **not** reproduced. It is not a single obvious
call; it requires auditing the full registered-route table for a permissive-gate/dangerous-callback pair
or a viable state-mutation chain, plus getting the drift arithmetic (number and position of malformed
sub-requests) to seat each stage correctly. That is genuine offensive R&D, not a one-liner.

---

## 4. Difficulty / time-to-weaponization read

| Capability | Effort | Basis |
|---|---|---|
| Detect vulnerable hosts | **Trivial** | Public non-destructive probe; deterministic `block_cannot_read` vs `rest_term_invalid`. Already in wide reach. |
| `allow_batch` allowlist bypass | **Low** | Demonstrated; direct from the primitive. |
| Reach a *gated* privileged handler | **Low–Med** | Drift arithmetic is simple; but you land on the handler's own gate. |
| **Unauth RCE (full chain)** | **Med–High** | Requires the item-3 permissive-gate/dangerous-callback or state-mutation chain across sub-requests. Route-table audit + reliable multi-stage drift. Skilled-researcher work. |

**Estimate inputs for the client memo (not the memo itself):** the *detection* half is already public and
commoditized, so exposed unpatched hosts are being fingerprinted now. The *weaponization* half is gated by
one non-trivial research step that the original disclosers deliberately held back and that a reviewed
public "PoC" (OffByOn3) failed to achieve (it faked it with post-auth admin-creation + webshell). History
for pre-auth WP core chains of this shape: a working public weapon typically lands **days-to-a-few-weeks**
after a credible primitive is public, accelerating sharply once *any* correct public chain drops. The
single highest-leverage risk signal to watch is the appearance of a *functional* public chain — at which
point time-to-mass-exploitation collapses to days.

---

## 5. Defensive implications (feeds Track 2)

- The malformed-first-sub-request shape is a **high-fidelity detection signature**: a `batch/v1` body whose
  first sub-request has an unparseable `path` is not something legitimate clients send. WAF/IDS can flag the
  `parse_path_failed`-inducing shape and/or the `block_cannot_read`-on-a-non-block-route response.
- Patch (7.0.2 / 6.9.5) is the real fix and closes it outright — confirmed by the A/B on this lab.
- No reliance on the `allow_batch` allowlist as a security boundary while unpatched — the desync defeats it.

---

## 6. Empirical results on the lab (non-destructive, "up to the line")

### 6a. The primitive is attacker-controllable (drift proof)

Same tail `[DELETE /categories/0, DELETE /tags/0, POST /block-renderer/core/paragraph]`, varying only
the number `k` of leading malformed sub-requests. Tracking **which handler adjudicates the fixed
categories `DELETE`**:

| k (leading malformed) | handler that judged the categories request | response |
|---|---|---|
| 0 | categories' own `delete_item` (correct) | `404 rest_term_invalid` |
| 1 | tags' `delete_item` (drift +1) | `404 rest_term_invalid` |
| 2 | block-renderer (drift +2) | `401 block_cannot_read` |

Each added malformed sub-request advances the adjudicating handler one slot down the valid-request list.
So an unauthenticated caller **deterministically selects which registered handler executes/authorizes a
given sub-request** — the real exploit primitive, proven with attacker control, well past a single error
code. Non-destructive throughout: nonexistent term IDs, unauthenticated, every misrouted handler denied.

### 6b. Batch sub-requests are write-method-only

A `GET` sub-request is rejected at the batch endpoint's own schema validation:
`requests[0][method] is not one of POST, PUT, PATCH, and DELETE`. So the desync can only *seat* handlers
that answer POST/PUT/PATCH/DELETE — i.e. the create/update/delete handlers, not public GET readers.

### 6c. Route-table audit of stock core 7.0 (decisive for the estimate)

Read-only introspection of `rest_get_server()->get_routes()`:

| metric | count |
|---|---|
| total registered handlers | 401 |
| batch-enabled handlers (donor slots) | 110 |
| **batch-enabled AND public-gated** | **0** |
| **public routes accepting any write method** | **0** |
| public routes overall | 3 (all GET: `/oembed/1.0/embed`, `/wp/v2/types/{type}`, `/wp/v2/users/me`) |

**Consequence — the single-shot unauth RCE path does not exist in stock core.** Every batch-reachable
(write-method) handler is gated by a real capability check (`*_permissions_check` → `current_user_can`),
and no such handler is public. Combined with 6a/6b: an unauthenticated attacker can aim the substitution
at any of the 110 batch handlers, but each still runs its own gate and denies. That is exactly why the
probe and every drift variant return *denials*, not execution.

### 6d. Revised weaponization read

Unauthenticated code execution against **stock** 7.0 core is therefore **not reachable in a single
request**. A working weapon requires one of:
- an **authenticated low-privilege** session crossing into a higher-privilege handler (post-auth priv-esc,
  not pre-auth);
- a **multi-stage state-mutation chain** (gate and callback are coupled per call, so "authorize as X,
  execute as Y" is only separable across sub-requests) — intricate and unproven; or
- a **plugin/theme that registers a public write or otherwise dangerous REST route** — common in the wild,
  and the most plausible real-world unauth path.

This materially **raises** the time-to-weaponization bar versus "trivially exploitable": the detection half
is public and commoditized, but a reliable *unauthenticated* core weapon is gated by a non-trivial chain
the disclosers withheld and that stock-core hardening actively resists. The dominant real-world risk is a
vulnerable plugin route reached through the desync — which is the scenario the client's plugin inventory
should drive.

**Ceiling reached without building a weapon:** attacker-controlled handler substitution is demonstrated;
onward unauth RCE is characterized, not constructed. Next step is to fully weaponize.
