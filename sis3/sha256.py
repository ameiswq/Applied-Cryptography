import struct


INITIAL_HASHES = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]

K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def _right_rotate(x: int, n: int):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _ch(x: int, y: int, z: int):
    return (x & y) ^ (~x & z)


def _maj(x: int, y: int, z: int):
    return (x & y) ^ (x & z) ^ (y & z)


def _big_sigma0(x: int):
    return _right_rotate(x, 2) ^ _right_rotate(x, 13) ^ _right_rotate(x, 22)


def _big_sigma1(x: int):
    return _right_rotate(x, 6) ^ _right_rotate(x, 11) ^ _right_rotate(x, 25)


def _small_sigma0(x: int):
    return _right_rotate(x, 7) ^ _right_rotate(x, 18) ^ (x >> 3)


def _small_sigma1(x: int):
    return _right_rotate(x, 17) ^ _right_rotate(x, 19) ^ (x >> 10)


def _pad_message(message: bytes):
    message_bit_length = len(message) * 8

    padded = message + b"\x80"

    while (len(padded) % 64) != 56:
        padded += b"\x00"

    padded += struct.pack(">Q", message_bit_length)
    return padded


def sha256_bytes(message: bytes):
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")

    h = INITIAL_HASHES.copy()
    padded = _pad_message(message)

    for i in range(0, len(padded), 64):
        chunk = padded[i:i + 64]

        w = list(struct.unpack(">16I", chunk))
        for t in range(16, 64):
            value = (
                _small_sigma1(w[t - 2]) +
                w[t - 7] +
                _small_sigma0(w[t - 15]) +
                w[t - 16]
            ) & 0xFFFFFFFF
            w.append(value)

        a, b, c, d, e, f, g, hh = h

        for t in range(64):
            temp1 = (hh + _big_sigma1(e) + _ch(e, f, g) + K[t] + w[t]) & 0xFFFFFFFF
            temp2 = (_big_sigma0(a) + _maj(a, b, c)) & 0xFFFFFFFF

            hh = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        h[0] = (h[0] + a) & 0xFFFFFFFF
        h[1] = (h[1] + b) & 0xFFFFFFFF
        h[2] = (h[2] + c) & 0xFFFFFFFF
        h[3] = (h[3] + d) & 0xFFFFFFFF
        h[4] = (h[4] + e) & 0xFFFFFFFF
        h[5] = (h[5] + f) & 0xFFFFFFFF
        h[6] = (h[6] + g) & 0xFFFFFFFF
        h[7] = (h[7] + hh) & 0xFFFFFFFF

    return b"".join(struct.pack(">I", value) for value in h)


def sha256_hex(message: bytes):
    return sha256_bytes(message).hex()


def sha256_text(text: str):
    if not isinstance(text, str):
        raise TypeError("Text must be str")

    return sha256_hex(text.encode("utf-8"))