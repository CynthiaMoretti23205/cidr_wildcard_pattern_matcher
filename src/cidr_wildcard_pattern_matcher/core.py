"""Core matching logic for legacy firewall-style IP wildcard patterns."""

from __future__ import annotations


class WildcardPatternMatcher:
    """Match IPv4 addresses against glob-style wildcard patterns.

    This class compiles patterns of the form ``192.168.*.*`` into a fixed
    tuple of masks. Each octet in the pattern is either a literal integer
    (``0``–``255``) or the wildcard ``*``. Matching is performed by XOR-ing
    each octet of the candidate address against the compiled literal and
    checking the bitwise-AND with the per-octet mask.

    Only dotted-decimal IPv4 with exactly four octets is supported. Hostnames,
    IPv6, and numeric shortcuts (leading zeros, octal) are rejected — the
    legacy firewall rule files this targets never accepted them either.
    """

    def __init__(self, pattern: str) -> None:
        """Compile *pattern* for later matching.

        Raises ``ValueError`` if the pattern does not have exactly four
        dot-separated octets, or if any non-wildcard octet is not an integer
        in the range 0–255.
        """
        self.pattern = pattern
        self._literals, self._masks = self._compile(pattern)

    @staticmethod
    def _compile(pattern: str) -> tuple[tuple[int, int, int, int], tuple[int, int, int, int]]:
        octets = pattern.split(".")
        if len(octets) != 4:
            raise ValueError(
                f"Pattern must have exactly 4 octets, got {len(octets)}: {pattern!r}"
            )
        literals: list[int] = []
        masks: list[int] = []
        for octet in octets:
            if octet == "*":
                # Mask of 0 means "any value matches this octet"; the
                # literal is irrelevant but zero keeps the tuple plain.
                literals.append(0)
                masks.append(0)
            else:
                # Reject leading zeros and signs by requiring the canonical
                # decimal form: no sign, no leading zero (except "0" itself),
                # digits only.
                if not octet.isdigit():
                    raise ValueError(
                        f"Invalid octet {octet!r} in pattern {pattern!r}: "
                        "must be 0-255 or '*'"
                    )
                if len(octet) > 1 and octet[0] == "0":
                    raise ValueError(
                        f"Invalid octet {octet!r} in pattern {pattern!r}: "
                        "leading zeros are not allowed"
                    )
                value = int(octet)
                if not 0 <= value <= 255:
                    raise ValueError(
                        f"Octet {value} out of range in pattern {pattern!r}"
                    )
                # Mask of 255 means "this octet must equal the literal".
                literals.append(value)
                masks.append(255)
        return tuple(literals), tuple(masks)  # type: ignore[return-value]

    def matches(self, address: str) -> bool:
        """Return ``True`` iff *address* matches the compiled pattern.

        *address* must be a dotted-decimal IPv4 with four octets, each
        in the range 0–255. Any deviation raises ``ValueError``.
        """
        parts = address.split(".")
        if len(parts) != 4:
            raise ValueError(
                f"Address must have exactly 4 octets, got {len(parts)}: {address!r}"
            )
        for part, literal, mask in zip(parts, self._literals, self._masks):
            if not part.isdigit():
                raise ValueError(
                    f"Invalid octet {part!r} in address {address!r}"
                )
            if len(part) > 1 and part[0] == "0":
                raise ValueError(
                    f"Invalid octet {part!r} in address {address!r}: "
                    "leading zeros are not allowed"
                )
            value = int(part)
            if not 0 <= value <= 255:
                raise ValueError(
                    f"Octet {value} out of range in address {address!r}"
                )
            # For literal octets: (value ^ literal) & 255 == 0 iff value == literal.
            # For wildcard octets: mask is 0, so the AND is always 0 → always matches.
            if (value ^ literal) & mask:
                return False
        return True

    def __repr__(self) -> str:
        return f"WildcardPatternMatcher(pattern={self.pattern!r})"
