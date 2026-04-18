def gcd(a: int, b: int) -> int:
    while b != 0:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int):
    if b == 0:
        return a, 1, 0

    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def mod_inverse(a: int, m: int):
    if m <= 0:
        raise ValueError("Modulus must be positive")

    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")

    return x % m


def mod_exp(base: int, exponent: int, modulus: int):
    if modulus <= 0:
        raise ValueError("Modulus must be positive")
    if exponent < 0:
        raise ValueError("Exponent must be non-negative")

    result = 1
    base %= modulus

    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1

    return result