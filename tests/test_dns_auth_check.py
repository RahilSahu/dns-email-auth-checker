import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dns_auth_check import analyse_dmarc, analyse_spf, check_domain


class SpfTests(unittest.TestCase):
    def test_missing_spf_fails(self):
        self.assertEqual(analyse_spf(["some other txt record"])[0], "fail")

    def test_hard_fail_passes(self):
        self.assertEqual(analyse_spf(["v=spf1 include:_spf.google.com -all"])[0], "pass")

    def test_plus_all_fails(self):
        self.assertEqual(analyse_spf(["v=spf1 +all"])[0], "fail")

    def test_softfail_warns(self):
        self.assertEqual(analyse_spf(["v=spf1 include:example.net ~all"])[0], "warn")


class DmarcTests(unittest.TestCase):
    def test_missing_dmarc_fails(self):
        self.assertEqual(analyse_dmarc([])[0], "fail")

    def test_reject_passes(self):
        self.assertEqual(analyse_dmarc(["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"])[0], "pass")

    def test_none_only_monitors(self):
        self.assertEqual(analyse_dmarc(["v=DMARC1; p=none"])[0], "warn")


FAKE_ANSWERS = {
    ("example.com", "MX"): ["10 mail.example.com."],
    ("example.com", "TXT"): ["v=spf1 -all"],
    ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
    ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
}


def fake_query(name, record_type):
    return FAKE_ANSWERS.get((name, record_type), [])


class CheckDomainTests(unittest.TestCase):
    def test_full_check_with_fake_dns(self):
        results = check_domain("example.com", query=fake_query)
        self.assertEqual(results["spf"]["status"], "pass")
        self.assertEqual(results["dmarc"]["status"], "pass")
        self.assertEqual(results["mx_status"][0], "pass")


if __name__ == "__main__":
    unittest.main()
