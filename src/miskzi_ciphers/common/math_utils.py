from __future__ import annotations


def gcd(a: int, b: int) -> int:
    """Return the greatest common divisor for integers a and b."""
    a = abs(a)
    b = abs(b)
    while b:
        a, b = b, a % b
    return a


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm: returns (g, x, y) where ax + by = g."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    g, x, y = old_r, old_s, old_t
    if g < 0:
        g, x, y = -g, -x, -y

    # internal consistency check
    assert a * x + b * y == g
    return g, x, y


def modinv(a: int, m: int) -> int:
    """Return modular inverse of a modulo m in range [0, m-1]."""
    if m <= 0:
        raise ValueError("modinv: modulus m must be > 0")

    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"modinv: inverse does not exist for a={a}, m={m} (gcd={g})")

    inv = x % m
    # internal consistency check
    assert (a * inv) % m == 1
    return inv
