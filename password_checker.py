"""
Project 1: Password Strength Checker - DecodeLabs (Batch 2026)
Cybersecurity Track - Defensive Logic / Junior Analyst

Goal: Create a program that checks whether a password is weak, medium, or strong.

IPO Model (O(n) linear scan):
  INPUT   : password string (raw byte stream via getpass, hidden input)
  PROCESS : single linear scan checks:
            1. Length verification: < 8 chars = immediate FAIL
               (exponential brute-force risk)
            2. Pattern recognition: mandatory [A-Z], [0-9], [symbols]
            3. Leaked-password check (constant-time compare)
            4. Unicode curveball: non-ASCII expands search space
               from 95 (ASCII) to 143,000+ (Unicode)
  OUTPUT  : Risk classification -> Weak / Medium / Strong + PASS/FAIL
            (Gatekeeper Rule: validation BEFORE encryption/hashing.
             "You cannot hash what is weak.")

Why this design:
- Pythonic: any(c.isdigit() for c in password) is C-optimized,
  short-circuiting, O(n) - not a verbose manual index loop.
- Secure compare: hmac.compare_digest() prevents timing attacks
  (fast-fail vs slow-fail leak).
- RAM note: Python strings are immutable and linger until GC,
  so we use getpass, avoid logging the password, and keep only booleans.
"""

import getpass
import hmac
import math
import string
from dataclasses import dataclass, field

# Small "leaked / common" denylist. Real systems check top-10k + HaveIBeenPwned.
# Stored lowercase for case-insensitive comparison.
COMMON_PASSWORDS = frozenset({
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "111111",
    "123123", "admin", "letmein", "welcome", "password1",
    "qwerty123", "1q2w3e4r", "admin123", "passw0rd", "password123",
    "000000", "iloveyou", "1234", "123", "dragon",
})

SPECIAL_CHARS = set(string.punctuation)  # 32 ASCII symbols


@dataclass
class CheckResult:
    password_length: int
    score: int          # 0-6
    strength: str       # Weak / Medium / Strong
    passed: bool        # Gatekeeper: True only if Strong
    entropy_bits: float
    checks: dict
    feedback: list = field(default_factory=list)


def _is_common_password(password: str) -> bool:
    """Constant-time check against denylist to avoid timing attacks.

    Normal `==` / `in` fails fast on first wrong char, leaking info
    via execution time. hmac.compare_digest() takes constant time.
    """
    lowered = password.lower()
    # Encode to bytes: compare_digest on str rejects non-ASCII,
    # on bytes it handles full Unicode safely (constant-time).
    lowered_b = lowered.encode("utf-8")
    return any(
        hmac.compare_digest(lowered_b, common.encode("utf-8"))
        for common in COMMON_PASSWORDS
    )


def check_password(password: str) -> CheckResult:
    """Check password strength. Raises TypeError if not a string."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    length = len(password)

    # --- PROCESS: Pythonic O(n) single-pass style checks ---
    # Each any() short-circuits on first match, C-optimized.
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)   # mandatory [A-Z]
    has_digit = any(c.isdigit() for c in password)   # mandatory [0-9]
    has_special = any(c in SPECIAL_CHARS for c in password)  # mandatory [symbols]
    # Unicode curveball: any non-ASCII char massively expands search space.
    has_unicode = any(ord(c) > 127 for c in password)
    # Non-ASCII letter/symbol also counts as "special" variety.
    has_non_ascii_variety = any(not c.isascii() for c in password)
    if has_non_ascii_variety:
        has_special = True

    length_8 = length >= 8
    length_12 = length >= 12
    no_spaces = " " not in password and "\t" not in password and "\n" not in password
    is_common = _is_common_password(password) if password else False
    not_common = not is_common

    checks = {
        "min_length_8": length_8,
        "length_12_plus": length_12,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_special": has_special,
        "has_unicode_bonus": has_unicode,
        "no_spaces": no_spaces,
        "not_common": not_common,
    }

    # Score 0-6: length8, lower, upper, digit, special, length12 bonus.
    score = sum([length_8, has_lower, has_upper, has_digit, has_special, length_12])

    # --- Entropy estimate (bits) ---
    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_special and not has_unicode:
        pool += 32
    if has_unicode:
        pool += 1000  # conservative proxy for 143k+ Unicode space
    if pool == 0:
        pool = 26  # lowercase-only guess baseline
    entropy_bits = round(length * math.log2(pool), 1) if length else 0.0

    # --- OUTPUT: risk classification (Weak / Medium / Strong) ---
    # Zero point policy: < 8 chars = immediate FAIL (Weak).
    if length < 8:
        strength = "Weak"
    elif is_common:
        strength = "Weak"  # leaked passwords are Weak regardless of shape
    else:
        categories = sum([has_lower, has_upper, has_digit, has_special])
        if categories == 4 and length_8:
            strength = "Strong"
        elif categories >= 2 and length_8:
            # Has decent variety but missing 1-2 classes -> Medium.
            # e.g. "Password123" (no symbol) -> Medium.
            strength = "Medium"
        else:
            strength = "Weak"

    # Gatekeeper rule: PASS only for Strong + clean hygiene.
    passed = (
        strength == "Strong"
        and length_8
        and not_common
        and no_spaces
    )

    feedback = []
    if length < 8:
        feedback.append("Use at least 8 characters (12+ recommended) - short passwords fall to brute force exponentially faster.")
    if not has_lower:
        feedback.append("Add lowercase letters (a-z).")
    if not has_upper:
        feedback.append("Add uppercase letters (A-Z).")
    if not has_digit:
        feedback.append("Add digits (0-9).")
    if not has_special:
        feedback.append("Add symbols (e.g. !@#$%^&*). Non-ASCII / emoji also works and expands entropy massively.")
    if not no_spaces:
        feedback.append("Avoid spaces/tabs/newlines.")
    if is_common:
        feedback.append("This is a common/leaked password - choose something unique.")
    if length_8 and not length_12:
        feedback.append("Consider 12+ characters for extra strength (entropy grows linearly with length).")

    return CheckResult(
        password_length=length,
        score=score,
        strength=strength,
        passed=passed,
        entropy_bits=entropy_bits,
        checks=checks,
        feedback=feedback,
    )


def print_result(result: CheckResult):
    status = "PASS (Gatekeeper: validated for hashing/encryption)" if result.passed else "FAIL (too weak to hash - fix first)"
    print(f"\nStrength: {result.strength} ({result.score}/6) - {status}")
    print(f"Length: {result.password_length} | Estimated entropy: ~{result.entropy_bits} bits")
    for name, ok in result.checks.items():
        print(f"  [{'x' if ok else ' '}] {name}")
    if result.feedback:
        print("\nSuggestions:")
        for tip in result.feedback:
            print(f"  - {tip}")
    else:
        print("\nExcellent! No suggestions.")


def main():
    print("=" * 60)
    print(" Project 1: Password Strength Checker")
    print(" DecodeLabs | Defensive Logic - 81% of breaches use weak/stolen passwords")
    print("=" * 60)
    try:
        pw = getpass.getpass("Enter password (hidden): ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return
    except Exception:
        # No TTY (e.g. IDE/pipe): fall back to visible input.
        try:
            pw = input("Enter password (visible fallback): ")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return
    if not pw:
        print("No password entered.")
        return
    result = check_password(pw)
    print_result(result)
    # Security hygiene: drop reference; immutable string is GC'd, not wiped.
    # (Python cannot overwrite strings in place - RAM-scraping note.)


if __name__ == "__main__":
    main()
