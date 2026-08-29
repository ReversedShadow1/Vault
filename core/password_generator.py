"""
Password generator for the "generate" button in the entry dialog.

Uses Python's `secrets` module (CSPRNG, os.urandom-backed) — not
`random`, and no custom shuffling/rejection-sampling logic that could
introduce bias. This isn't "cryptography" in the KDF/cipher sense but
the same "never hand-roll" principle applies to randomness sourcing.
"""

import secrets
import string


LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"


def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    if length < 8:
        raise ValueError("Generated passwords should be at least 8 characters.")

    pools = [LOWER]
    if use_upper:
        pools.append(UPPER)
    if use_digits:
        pools.append(DIGITS)
    if use_symbols:
        pools.append(SYMBOLS)

    alphabet = "".join(pools)

    # Guarantee at least one char from each selected pool, rest random —
    # avoids the case where a fully random draw happens to omit a
    # required character class.
    required = [secrets.choice(pool) for pool in pools]
    remaining_len = length - len(required)
    rest = [secrets.choice(alphabet) for _ in range(remaining_len)]

    chars = required + rest
    # Fisher-Yates shuffle using secrets.randbelow (unbiased, CSPRNG-backed)
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)
