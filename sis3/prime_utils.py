from math_utils import mod_exp
from rng import randbits, randbelow


def default_miller_rabin_rounds(bits: int):
    if bits >= 1024:
        return 64
    if bits >= 512:
        return 40
    return 20


def random_odd_int(bits: int):
    if bits < 2:
        raise ValueError("Bit length must be at least 2")

    num = randbits(bits)
    num |= (1 << (bits - 1)) 
    num |= 1              
    return num


def is_probable_prime(n: int, k: int | None = None):
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]

    if n in small_primes:
        return True

    if n % 2 == 0:
        return False

    for p in small_primes[1:]:
        if n % p == 0:
            return False

    bits = n.bit_length()
    if k is None:
        k = default_miller_rabin_rounds(bits)

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = randbelow(n - 3) + 2 
        x = mod_exp(a, d, n)

        if x == 1 or x == n - 1:
            continue

        passed_round = False
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                passed_round = True
                break

        if not passed_round:
            return False

    return True


def generate_prime(bits: int, k: int | None = None):
    if bits < 2:
        raise ValueError("Bit length must be at least 2")

    while True:
        candidate = random_odd_int(bits)
        if is_probable_prime(candidate, k):
            return candidate


def generate_distinct_primes(bits: int, k: int | None = None):
    p = generate_prime(bits, k)
    q = generate_prime(bits, k)

    while q == p:
        q = generate_prime(bits, k)

    return p, q