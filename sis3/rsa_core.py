from dataclasses import dataclass
from math_utils import gcd, mod_inverse, mod_exp
from prime_utils import generate_distinct_primes, is_probable_prime
from padding import (pkcs1_v15_pad, pkcs1_v15_unpad, pkcs1_v15_signature_pad,
                    pkcs1_v15_signature_verify, oaep_pad, oaep_unpad,)
from sha256 import sha256_bytes


@dataclass
class PublicKey:
    n: int
    e: int


@dataclass
class PrivateKey:
    n: int
    d: int
    p: int
    q: int


def bytes_to_int(data: bytes):
    return int.from_bytes(data, byteorder="big")


def int_to_bytes(value: int, min_length: int = 0):
    if value < 0:
        raise ValueError("Value must be non-negative")

    if value == 0:
        result = b"\x00"
    else:
        length = (value.bit_length() + 7) // 8
        result = value.to_bytes(length, byteorder="big")

    if min_length > 0 and len(result) < min_length:
        result = b"\x00" * (min_length - len(result)) + result

    return result


def modulus_byte_length(n: int):
    return (n.bit_length() + 7) // 8


def generate_keypair(bits: int = 1024, e: int = 65537):
    if bits < 16:
        raise ValueError("Key size is too small")
    if bits % 2 != 0:
        raise ValueError("Key size must be even")
    if e <= 1 or e % 2 == 0:
        raise ValueError("Public exponent e must be odd and greater than 1")

    prime_bits = bits // 2

    while True:
        p, q = generate_distinct_primes(prime_bits)

        if abs(p - q) < (1 << max(prime_bits - 100, 1)):
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        if gcd(e, phi) != 1:
            continue

        d = mod_inverse(e, phi)

        public_key = PublicKey(n=n, e=e)
        private_key = PrivateKey(n=n, d=d, p=p, q=q)

        return public_key, private_key


def encrypt_int(message_int: int, public_key: PublicKey):
    if message_int < 0:
        raise ValueError("Message integer must be non-negative")
    if message_int >= public_key.n:
        raise ValueError("Message integer must be less than modulus n")

    return mod_exp(message_int, public_key.e, public_key.n)


def decrypt_int(cipher_int: int, private_key: PrivateKey):
    if cipher_int < 0:
        raise ValueError("Cipher integer must be non-negative")
    if cipher_int >= private_key.n:
        raise ValueError("Cipher integer must be less than modulus n")

    return mod_exp(cipher_int, private_key.d, private_key.n)


def encrypt_bytes(message: bytes, public_key: PublicKey, padding_mode: str = "pkcs1v15"):
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")

    k = modulus_byte_length(public_key.n)

    if padding_mode == "pkcs1v15":
        padded_message = pkcs1_v15_pad(message, k)
    elif padding_mode == "oaep":
        padded_message = oaep_pad(message, k)
    else:
        raise ValueError("Unsupported padding mode")

    message_int = bytes_to_int(padded_message)
    cipher_int = encrypt_int(message_int, public_key)

    return int_to_bytes(cipher_int, min_length=k)


def decrypt_bytes(ciphertext: bytes, private_key: PrivateKey, padding_mode: str = "pkcs1v15"):
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")

    k = modulus_byte_length(private_key.n)

    if len(ciphertext) != k:
        raise ValueError("Ciphertext length does not match key size")

    cipher_int = bytes_to_int(ciphertext)
    message_int = decrypt_int(cipher_int, private_key)
    padded_message = int_to_bytes(message_int, min_length=k)

    if padding_mode == "pkcs1v15":
        return pkcs1_v15_unpad(padded_message)
    elif padding_mode == "oaep":
        return oaep_unpad(padded_message)
    else:
        raise ValueError("Unsupported padding mode")


def sign_message(message: bytes, private_key: PrivateKey):
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")

    k = modulus_byte_length(private_key.n)

    digest = sha256_bytes(message)
    encoded_message = pkcs1_v15_signature_pad(digest, k)

    em_int = bytes_to_int(encoded_message)
    signature_int = mod_exp(em_int, private_key.d, private_key.n)

    return int_to_bytes(signature_int, min_length=k)


def verify_message(message: bytes, signature: bytes, public_key: PublicKey):
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")
    if not isinstance(signature, bytes):
        raise TypeError("Signature must be bytes")

    k = modulus_byte_length(public_key.n)

    if len(signature) != k:
        return False

    signature_int = bytes_to_int(signature)
    if signature_int >= public_key.n:
        return False

    recovered_int = mod_exp(signature_int, public_key.e, public_key.n)
    recovered_em = int_to_bytes(recovered_int, min_length=k)

    digest = sha256_bytes(message)
    return pkcs1_v15_signature_verify(recovered_em, digest)

def validate_public_key(public_key: PublicKey):
    if public_key.n <= 1:
        return False
    if public_key.e <= 1:
        return False
    if public_key.e % 2 == 0:
        return False

    return True


def validate_private_key(private_key: PrivateKey):
    if private_key.n <= 1:
        return False
    if private_key.d <= 1:
        return False
    if private_key.p <= 1 or private_key.q <= 1:
        return False
    if private_key.p == private_key.q:
        return False

    if not is_probable_prime(private_key.p):
        return False
    if not is_probable_prime(private_key.q):
        return False

    if private_key.p * private_key.q != private_key.n:
        return False

    return True


def validate_key_pair(public_key: PublicKey, private_key: PrivateKey):
    if not validate_public_key(public_key):
        return False

    if not validate_private_key(private_key):
        return False

    if public_key.n != private_key.n:
        return False

    phi = (private_key.p - 1) * (private_key.q - 1)

    if gcd(public_key.e, phi) != 1:
        return False

    if (public_key.e * private_key.d) % phi != 1:
        return False

    return True