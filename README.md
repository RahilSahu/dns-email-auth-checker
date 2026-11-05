# DNS Email Auth Checker

A small, zero-dependency Python tool that checks whether a domain is
protected against email spoofing, and explains the result in plain
language.

Email spoofing still works against most domains simply because the
three records that stop it were never set up, or were set up in
monitor-only mode and forgotten. This tool checks all of them in one run.

## What it checks

- MX: can the domain receive mail at all
- SPF: which servers may send for the domain, and whether the policy
  ends in -all, ~all, ?all, or the dangerous +all
- DMARC: whether a record exists at _dmarc, and whether the policy is
  p=reject, p=quarantine, or monitor-only p=none
- DKIM: common selectors under _domainkey (best effort, selector names
  are not public information)
- CAA: whether certificate issuance for the domain is restricted

Queries use DNS-over-HTTPS (Google Public DNS), so no local DNS tools
are needed and the checker works on restricted networks.

## Usage

```bash
python3 dns_auth_check.py example.com
python3 dns_auth_check.py example.com --json
```

Example output:

```text
Domain: example.com

  MX: 10 mail.example.com.
[PASS] Mail (MX): 1 MX record(s) found.
[PASS] SPF: SPF present with a hard fail (-all) for unauthorised senders.
[WARN] DMARC: DMARC policy is p=none. This only monitors, it does not protect the domain.
```

## Requirements

Python 3.9 or newer. No packages to install.

## Tests

The SPF and DMARC analysis is fully unit tested offline, and the full
domain check is tested against a fake DNS resolver:

```bash
python3 -m unittest discover -s tests
```

## Responsible use

DNS records are public information and this tool only reads them.
Still, use assessment findings responsibly and report issues to the
domain owner.

## License

MIT, see LICENSE.
