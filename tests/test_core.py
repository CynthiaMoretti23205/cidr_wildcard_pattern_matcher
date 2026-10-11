import unittest

from cidr_wildcard_pattern_matcher import WildcardPatternMatcher


class TestCompile(unittest.TestCase):
    def test_repr(self):
        m = WildcardPatternMatcher("10.0.0.0")
        self.assertEqual(repr(m), "WildcardPatternMatcher(pattern='10.0.0.0')")

    def test_pattern_stored(self):
        m = WildcardPatternMatcher("192.168.*.*")
        self.assertEqual(m.pattern, "192.168.*.*")


class TestMatchesLiteral(unittest.TestCase):
    def test_exact_literal_match(self):
        self.assertTrue(WildcardPatternMatcher("10.0.0.1").matches("10.0.0.1"))

    def test_literal_no_match(self):
        self.assertFalse(WildcardPatternMatcher("10.0.0.1").matches("10.0.0.2"))

    def test_zero_boundary_matches(self):
        self.assertTrue(WildcardPatternMatcher("0.0.0.0").matches("0.0.0.0"))

    def test_max_boundary_matches(self):
        self.assertTrue(WildcardPatternMatcher("255.255.255.255").matches("255.255.255.255"))

    def test_partial_mismatch(self):
        self.assertFalse(WildcardPatternMatcher("10.0.0.1").matches("10.0.0.2"))


class TestMatchesWildcard(unittest.TestCase):
    def test_all_wildcards_match_anything(self):
        self.assertTrue(WildcardPatternMatcher("*.*.*.*").matches("1.2.3.4"))

    def test_prefix_wildcard_suffix(self):
        self.assertTrue(WildcardPatternMatcher("192.168.*.*").matches("192.168.0.1"))
        self.assertTrue(WildcardPatternMatcher("192.168.*.*").matches("192.168.99.200"))

    def test_prefix_no_match(self):
        self.assertFalse(WildcardPatternMatcher("192.168.*.*").matches("10.0.0.1"))

    def test_suffix_wildcard_prefix(self):
        self.assertTrue(WildcardPatternMatcher("*.*.0.1").matches("192.168.0.1"))
        self.assertFalse(WildcardPatternMatcher("*.*.0.1").matches("192.168.0.2"))

    def test_middle_wildcards(self):
        self.assertTrue(WildcardPatternMatcher("10.*.*.1").matches("10.20.30.1"))
        self.assertFalse(WildcardPatternMatcher("10.*.*.1").matches("10.20.30.2"))


class TestAddressValidation(unittest.TestCase):
    def test_address_wrong_octet_count(self):
        with self.assertRaises(ValueError):
            WildcardPatternMatcher("*.*.*.*").matches("1.2.3")

    def test_address_non_numeric(self):
        with self.assertRaises(ValueError):
            WildcardPatternMatcher("*.*.*.*").matches("a.b.c.d")

    def test_address_octet_out_of_range(self):
        with self.assertRaises(ValueError):
            WildcardPatternMatcher("*.*.*.*").matches("1.2.3.256")


class TestPatternValidation(unittest.TestCase):
    def test_pattern_wrong_octet_count(self):
        with self.assertRaises(ValueError):
            WildcardPatternMatcher("10.0.0")

    def test_pattern_non_numeric_octet(self):
        with self.assertRaises(ValueError):
            WildcardPatternMatcher("10.x.0.1")

    def test_pattern_octet_out_of_range(self):
        with self.assertRaises(ValueError):
            WildcardPatternMatcher("10.256.0.1")

    def test_pattern_leading_zero_rejected(self):
        # Leading zeros look like octal to some parsers. Reject to avoid ambiguity.
        with self.assertRaises(ValueError):
            WildcardPatternMatcher("10.001.0.1")

    def test_pattern_plus_sign_rejected(self):
        with self.assertRaises(ValueError):
            WildcardPatternMatcher("10.+5.0.1")


if __name__ == "__main__":
    unittest.main()
