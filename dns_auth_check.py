#!/usr/bin/env python3
"""DNS and email authentication checker.

Looks up the DNS records that decide whether email sent from a domain
can be trusted, and whether the domain is set up correctly:

- MX records (where mail for the domain goes)
- SPF (which servers may send mail for the domain)
- DMARC (what receivers should do with mail that fails checks, and
  whether the policy actually enforces anything)
- DKIM for common selectors (best effort, selectors are not public)
- CAA (which certificate authorities may issue certs for the domain)

Queries run over DNS-over-HTTPS (Google Public DNS JSON API), so the
tool needs no local DNS tools and works behind restrictive networks.
Zero dependencies: Python 3.9+ standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request

DOH_ENDPOINT = "https://dns.google/resolve"
USER_AGENT = "dns-auth-check/1.0 (+https://github.com/RahilSahu/dns-email-auth-checker)"
COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "s1", "s2", "mail", "dkim"]


def doh_query(name: str, record_type: str) -> list[str]:
    """Return the answer strings for one DNS-over-HTTPS query."""
    query = urllib.parse.urlencode({"name": name, "type": record_type})
    request = urllib.request.Request(
        f"{DOH_ENDPOINT}?{query}",
        headers={"User-Agent": USER_AGENT, "Accept": "application/dns-json"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = json.load(response)
    answers = []
    for answer in payload.get("Answer", []):
        answers.append(str(answer.get("data", "")).strip().strip('"'))
    return answers


def find_record(records: list[str], prefix: str) -> str | None:
    for record in records:
        if record.lower().startswith(prefix.lower()):
            return record
    return None


def analyse_spf(records: list[str]) -> tuple[str, str]:
    """Return (status, detail) for SPF."""
    spf = find_record(records, "v=spf1")
    if not spf:
        return "fail", "No SPF record. Anyone can spoof mail from this domain."
    if spf.count("v=spf1") > 1 or len([r for r in records if r.lower().startswith("v=spf1")]) > 1:
        return "fail", "Multiple SPF records found. SPF will fail validation (PermError)."
    lowered = spf.lower()
    if lowered.rstrip().endswith("+all"):
        return "fail", "SPF ends in +all, which authorises every server on the internet to send for this domain."
    if lowered.rstrip().endswith("?all"):
        return "warn", "SPF ends in ?all (neutral). It documents senders but does not reject anyone else."
    if lowered.rstrip().endswith("~all"):
        return "warn", "SPF ends in ~all (softfail). Better than nothing, pair it with a DMARC reject policy."
    if lowered.rstrip().endswith("-all"):
        return "pass", "SPF present with a hard fail (-all) for unauthorised senders."
    return "warn", "SPF record present but has no explicit all mechanism at the end."


def analyse_dmarc(records: list[str]) -> tuple[str, str]:
    """Return (status, detail) for DMARC."""
    dmarc = find_record(records, "v=DMARC1")
    if not dmarc:
        return "fail", "No DMARC record at _dmarc. Receivers get no instruction for spoofed mail."
    lowered = dmarc.lower()
    if "p=reject" in lowered:
        return "pass", "DMARC policy is p=reject. Failing mail is rejected."
    if "p=quarantine" in lowered:
        return "warn", "DMARC policy is p=quarantine. Failing mail goes to spam, but is not rejected."
    if "p=none" in lowered:
        return "warn", "DMARC policy is p=none. This only monitors, it does not protect the domain."
    return "warn", "DMARC record found but no clear policy (p=) value."


def check_domain(domain: str, query=doh_query) -> dict:
    """Run all checks. `query` is injectable so tests can run offline."""
    domain = domain.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    results: dict = {"domain": domain}

    mx = query(domain, "MX")
    results["mx"] = mx
    results["mx_status"] = ("pass", f"{len(mx)} MX record(s) found.") if mx else ("fail", "No MX records. This domain cannot receive mail.")

    txt = query(domain, "TXT")
    spf_status, spf_detail = analyse_spf(txt)
    results["spf"] = {"record": find_record(txt, "v=spf1"), "status": spf_status, "detail": spf_detail}

    dmarc_txt = query(f"_dmarc.{domain}", "TXT")
    dmarc_status, dmarc_detail = analyse_dmarc(dmarc_txt)
    results["dmarc"] = {"record": find_record(dmarc_txt, "v=DMARC1"), "status": dmarc_status, "detail": dmarc_detail}

    dkim_found = []
    for selector in COMMON_DKIM_SELECTORS:
        found = query(f"{selector}._domainkey.{domain}", "TXT")
        if any("v=dkim1" in r.lower() or "p=" in r for r in found):
            dkim_found.append(selector)
    results["dkim_selectors_found"] = dkim_found
    results["dkim_status"] = ("pass", f"DKIM record found for selector(s): {', '.join(dkim_found)}.") if dkim_found else (
        "warn", "No DKIM record found for common selectors. DKIM may still exist under another selector name.")

    caa = query(domain, "CAA")
    results["caa"] = caa
    results["caa_status"] = ("pass", "CAA records present, certificate issuance is restricted.") if caa else (
        "warn", "No CAA records. Any certificate authority may issue certificates for this domain.")
    return results


def print_results(r: dict) -> None:
    def line(label, item):
        status, detail = item
        print(f"[{status.upper()}] {label}: {detail}")

    print(f"\nDomain: {r['domain']}\n")
    for entry in r["mx"]:
        print(f"  MX: {entry}")
    line("Mail (MX)", r["mx_status"])
    line("SPF", (r["spf"]["status"], r["spf"]["detail"]))
    if r["spf"]["record"]:
        print(f"       Record: {r['spf']['record']}")
    line("DMARC", (r["dmarc"]["status"], r["dmarc"]["detail"]))
    if r["dmarc"]["record"]:
        print(f"       Record: {r['dmarc']['record']}")
    line("DKIM", r["dkim_status"])
    line("CAA", r["caa_status"])
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check DNS email authentication (SPF, DMARC, DKIM) and related records.")
    parser.add_argument("domain", help="Domain to check, for example example.com")
    parser.add_argument("--json", action="store_true", help="Print results as JSON")
    args = parser.parse_args(argv)

    try:
        results = check_domain(args.domain)
    except Exception as exc:  # network or DNS-over-HTTPS failure
        print(f"Error: could not check {args.domain}: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_results(results)
    fails = [results["mx_status"][0], results["spf"]["status"], results["dmarc"]["status"]]
    return 1 if "fail" in fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
