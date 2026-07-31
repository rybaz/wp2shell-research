# Credits & provenance

This repository is an independent research reconstruction of the "wp2shell" chain
(CVE-2026-63030 + CVE-2026-60137). Being precise about who found what is part of the
point of the project, so:

## Original disclosure
- **Hadrian** — published the CVE-2026-63030 REST batch route-confusion desync and a
  detection probe, and asserted an unauthenticated RCE against a stock install, while
  deliberately withholding the escalation details.

## Reconstructed independently here
From the public Hadrian post, the public patch diff (`c8bdf1fa1235`), and reading the
WordPress 7.0.1 source, this project independently derived:
- the **nested (batch-in-batch)** reachability from the desync to the posts `get_items`
  handler, and the `author__not_in` **SQL injection** (CVE-2026-60137) it contains;
- the UNION / boolean-blind **database read** (`sqli`);
- the read-to-write **oEmbed cache bridge** (fabricated post ID 0 → `oembed_cache` insert);
- the escalation **sink**: the Customizer changeset identity-borrow in
  `WP_Customize_Manager::_publish_changeset_values()` (`wp_set_current_user($setting_user_id)`),
  its `transition_post_status` trigger, and the past-dated `future`→`publish` flip. This is
  the specific mechanism the disclosure held back, and it was findable from the
  patch-adjacent source alone.

## Taken from prior public work
- **shinthink** — [`github.com/shinthink/CVE-2026-63030`](https://github.com/shinthink/CVE-2026-63030).
  The **trigger geometry** that welds the sink into a working unauthenticated exploit —
  routing an anonymous `wp_update_post` through the oEmbed cache refresh and a
  post-hierarchy-loop cascade onto the forged changeset, and the shape of the forged
  post set — is taken from shinthink's public full-chain PoC. The `core-rce` command
  (`src/wp2shell/takeover.py`) reproduces that geometry. Our end-to-end reproduction
  landed only after adopting it.
- **mverschu** — [`github.com/mverschu/CVE-2026-63030`](https://github.com/mverschu/CVE-2026-63030) —
  listed for completeness; not used here.

See [`docs/analysis.md`](docs/analysis.md) §4.2 for the full mechanism and the same
provenance boundary stated inline.
