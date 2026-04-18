import secrets

from sha256 import sha256_bytes


SHA256_DIGESTINFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


def pkcs1_v15_pad(message: bytes, block_size: int):
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")

    if block_size < 11:
        raise ValueError("Block size is too small")

    max_message_length = block_size - 11
    if len(message) > max_message_length:
        raise ValueError("Message is too long")

    padding_length = block_size - len(message) - 3

    ps = bytearray()
    while len(ps) < padding_length:
        b = secrets.randbelow(256)
        if b != 0:
            ps.append(b)

    return b"\x00\x02" + bytes(ps) + b"\x00" + message


def pkcs1_v15_unpad(padded_message: bytes):
    if not isinstance(padded_message, bytes):
        raise TypeError("Padded message must be bytes")

    if len(padded_message) < 11:
        raise ValueError("Padded message is too short")

    if padded_message[0] != 0x00 or padded_message[1] != 0x02:
        raise ValueError("Invalid PKCS#1 v1.5 header")

    separator_index = padded_message.find(b"\x00", 2)
    if separator_index == -1:
        raise ValueError("Padding separator not found")

    ps = padded_message[2:separator_index]
    if len(ps) < 8:
        raise ValueError("Padding string is too short")

    if any(b == 0 for b in ps):
        raise ValueError("Padding string contains zero byte")

    return padded_message[separator_index + 1:]


def pkcs1_v15_signature_pad(hash_bytes: bytes, block_size: int):
    if not isinstance(hash_bytes, bytes):
        raise TypeError("Hash must be bytes")

    digest_info = SHA256_DIGESTINFO_PREFIX + hash_bytes

    if len(digest_info) + 11 > block_size:
        raise ValueError("Digest is too long for this key size")

    padding_length = block_size - len(digest_info) - 3
    if padding_length < 8:
        raise ValueError("Not enough space for signature padding")

    return b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info


def pkcs1_v15_signature_verify(encoded_message: bytes, hash_bytes: bytes):
    if not isinstance(encoded_message, bytes):
        raise TypeError("Encoded message must be bytes")
    if not isinstance(hash_bytes, bytes):
        raise TypeError("Hash must be bytes")

    expected_digest_info = SHA256_DIGESTINFO_PREFIX + hash_bytes

    if len(encoded_message) < len(expected_digest_info) + 11:
        return False

    if encoded_message[0] != 0x00 or encoded_message[1] != 0x01:
        return False

    separator_index = encoded_message.find(b"\x00", 2)
    if separator_index == -1:
        return False

    ps = encoded_message[2:separator_index]
    if len(ps) < 8:
        return False

    if any(b != 0xFF for b in ps):
        return False

    digest_info = encoded_message[separator_index + 1:]
    return digest_info == expected_digest_info


def mgf1(seed: bytes, mask_len: int):
    if mask_len < 0:
        raise ValueError("mask_len must be non-negative")

    output = b""
    counter = 0

    while len(output) < mask_len:
        c = counter.to_bytes(4, byteorder="big")
        output += sha256_bytes(seed + c)
        counter += 1

    return output[:mask_len]


def oaep_pad(message: bytes, block_size: int, label: bytes = b""):
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")
    if not isinstance(label, bytes):
        raise TypeError("Label must be bytes")

    h_len = 32
    if block_size < 2 * h_len + 2:
        raise ValueError("Block size is too small for OAEP")

    max_message_length = block_size - 2 * h_len - 2
    if len(message) > max_message_length:
        raise ValueError("Message is too long")

    l_hash = sha256_bytes(label)
    ps = b"\x00" * (block_size - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message

    seed = secrets.token_bytes(h_len)
    db_mask = mgf1(seed, block_size - h_len - 1)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))

    seed_mask = mgf1(masked_db, h_len)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

    return b"\x00" + masked_seed + masked_db


def oaep_unpad(encoded_message: bytes, label: bytes = b""):
    if not isinstance(encoded_message, bytes):
        raise TypeError("Encoded message must be bytes")
    if not isinstance(label, bytes):
        raise TypeError("Label must be bytes")

    h_len = 32

    if len(encoded_message) < 2 * h_len + 2:
        raise ValueError("Encoded message is too short")

    if encoded_message[0] != 0x00:
        raise ValueError("Invalid OAEP header")

    masked_seed = encoded_message[1:1 + h_len]
    masked_db = encoded_message[1 + h_len:]

    seed_mask = mgf1(masked_db, h_len)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))

    db_mask = mgf1(seed, len(masked_db))
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    l_hash = sha256_bytes(label)
    l_hash_recovered = db[:h_len]

    if l_hash_recovered != l_hash:
        raise ValueError("OAEP label hash mismatch")

    rest = db[h_len:]
    separator_index = rest.find(b"\x01")
    if separator_index == -1:
        raise ValueError("OAEP separator not found")

    padding_part = rest[:separator_index]
    if any(b != 0x00 for b in padding_part):
        raise ValueError("Invalid OAEP zero padding")

    return rest[separator_index + 1:]