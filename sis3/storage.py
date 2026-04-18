import json
import base64
from pathlib import Path

from rsa_core import PublicKey, PrivateKey


def save_public_key(public_key: PublicKey, file_path: str):
    data = {
        "type": "public",
        "n": format(public_key.n, "x"),
        "e": format(public_key.e, "x"),
    }

    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def save_private_key(private_key: PrivateKey, file_path: str):
    data = {
        "type": "private",
        "n": format(private_key.n, "x"),
        "d": format(private_key.d, "x"),
        "p": format(private_key.p, "x"),
        "q": format(private_key.q, "x"),
    }

    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def load_public_key(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if data.get("type") != "public":
        raise ValueError("File does not contain a public key")

    if "n" not in data or "e" not in data:
        raise ValueError("Invalid public key format")

    return PublicKey(
        n=int(data["n"], 16),
        e=int(data["e"], 16),
    )


def load_private_key(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if data.get("type") != "private":
        raise ValueError("File does not contain a private key")

    required_fields = ["n", "d", "p", "q"]
    for field in required_fields:
        if field not in data:
            raise ValueError("Invalid private key format")

    return PrivateKey(
        n=int(data["n"], 16),
        d=int(data["d"], 16),
        p=int(data["p"], 16),
        q=int(data["q"], 16),
    )


def save_text(text: str, file_path: str):
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def load_text(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def save_bytes(data: bytes, file_path: str):
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "wb") as f:
        f.write(data)


def load_bytes(file_path: str):
    with open(file_path, "rb") as f:
        return f.read()


def save_hex(data: bytes, file_path: str):
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        f.write(data.hex())


def load_hex(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        hex_data = f.read().strip()

    return bytes.fromhex(hex_data)

def save_base64(data: bytes, file_path: str):
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    encoded = base64.b64encode(data).decode("utf-8")

    with open(path, "w", encoding="utf-8") as f:
        f.write(encoded)


def load_base64(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        encoded = f.read().strip()

    return base64.b64decode(encoded.encode("utf-8"))