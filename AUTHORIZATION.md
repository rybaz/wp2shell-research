# Authorization & Responsible Use

This repository contains a **working proof-of-concept** for an unauthenticated
WordPress compromise chain (CVE-2026-63030 + CVE-2026-60137). It is published for
**defensive security research, detection engineering, and authorized testing
only**.

## You MUST have authorization

Run these tools **only** against systems that meet **all** of the following:

- You own them, **or** you have **explicit written authorization** to test them
  (e.g. a signed engagement scope, a bug-bounty program that covers the target,
  or your own lab), **and**
- They are on an **isolated / non-production** network wherever possible.

Unauthorized use against systems you do not own or have permission to test is
illegal in most jurisdictions and is not condoned by the authors.

## What these tools do (so there are no surprises)

- `check` / `probe` — **non-destructive.** Only unauthenticated requests against
  non-existent term ids; nothing is created, modified, or deleted.
- `sqli` — **reads** database contents (including password hashes) via SQL
  injection. It does not write to the database, but extracting credential
  material is high-impact — treat output as sensitive.
- `write-exec` — **writes a file and achieves code execution.** It plants a
  **benign** PHP file (default: prints `6*7`; no shell, no input handling) and
  fetches it to prove execution, then overwrites it with an inert stub. It needs a
  **deliberately vulnerable lab plugin** (`lab/acme-templates.php`) that you install
  yourself on an isolated test instance — do not deploy that plugin anywhere real,
  and keep the payload non-destructive.
- `seat` — exercises the desync primitive directly (research).

## Handling of extracted data

Any credentials, hashes, or database contents obtained during authorized testing
are sensitive. Store them per your engagement's rules of engagement, share them
only with authorized parties, and destroy them when the engagement ends. The
example outputs in this repo's docs are **redacted**.

## No target lists, no automation for scale

These tools operate on a **single, explicitly-specified target**. They contain no
scanning, no target discovery, and no mass-exploitation functionality — by design.

## Remediation is the point

The real deliverable is defense: patch WordPress core to **≥ 7.0.2 / ≥ 6.9.5**,
apply the detection signatures in `docs/analysis.md`, and audit plugins/themes for
permissive REST write routes. See `docs/analysis.md` §5.
