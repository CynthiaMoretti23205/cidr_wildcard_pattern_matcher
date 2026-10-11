# cidr_wildcard_pattern_matcher

A small library for matching IPv4 addresses against glob-style wildcard patterns like `192.168.*.*`, the form found in legacy firewall and access-control rule files.

```python
from cidr_wildcard_pattern_matcher import WildcardPatternMatcher

matcher = WildcardPatternMatcher("192.168.*.*")
matcher.matches("192.168.0.1")   # True
matcher.matches("10.0.0.1")       # False
```

## Why this exists

Migrating legacy firewall rules often means translating glob-style patterns into CIDR notation. Before translating, it is useful to have a standalone matcher that can replay a captured traffic log against the original rules to verify the migration preserved behaviour. Standard CIDR libraries do not understand `*` octets, and hand-rolled `fnmatch` calls conflate `*` as "any sequence" with `*` as "one octet" — the distinction matters when the string `192.168.1.10` is checked against `192.168.1.*`. `fnmatch` handles it; but `192.168.*.*` against `192.168.1` (three octets) will also match under `fnmatch`, which is wrong for IP semantics. This library enforces exactly four octets on both sides.

## Edge cases

- Only dotted-decimal IPv4 with four octets is accepted. IPv6, hostnames, and leading-zero octal forms (`010`) are rejected with `ValueError`.
- The wildcard `*` matches one whole octet (any value 0–255), not an arbitrary run of characters.
- Addresses and patterns with fewer or more than four dot-separated fields raise `ValueError`.
