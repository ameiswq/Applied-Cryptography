import os

### это для паддинга
def randbytes(n: int):
    if n <= 0:
        raise ValueError("n must be positive")
    return os.urandom(n)

### это для генерации кандидатов
def randbits(k: int):
    if k <= 0:
        raise ValueError("k must be positive")

    num_bytes = (k + 7) // 8
    random_bytes = os.urandom(num_bytes)
    value = int.from_bytes(random_bytes, "big")
    return value & ((1 << k) - 1)

## для проверки миллер рабин
def randbelow(n: int):
    if n <= 0:
        raise ValueError("n must be positive")
    n_bits = n.bit_length()
    while True:
        candidate = randbits(n_bits)
        if candidate < n:
            return candidate
