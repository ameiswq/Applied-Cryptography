import base64

from rsa_core import (
    generate_keypair,
    encrypt_bytes,
    decrypt_bytes,
    sign_message,
    verify_message,
    validate_public_key,
    validate_private_key,
    validate_key_pair,
)
from storage import (
    save_public_key,
    save_private_key,
    load_public_key,
    load_private_key,
    save_hex,
    load_hex,
    save_base64,
    load_base64,
    save_text,
    load_text,
)
from sha256 import sha256_text


def print_menu() -> None:
    print("\n------RSA CLI MENU-------")
    print("1. Generate key pair")
    print("2. Encrypt message")
    print("3. Decrypt message")
    print("4. Hash text with SHA-256")
    print("5. Sign message")
    print("6. Verify signature")
    print("7. Show key info")
    print("8. Validate key files")
    print("9. Save text to file")
    print("10. Load text from file")
    print("0. Exit")


def choose_padding():
    print("Choose padding:")
    print("1. PKCS#1 v1.5")
    print("2. OAEP")

    choice = input("Enter choice: ").strip()

    if choice == "1":
        return "pkcs1v15"
    if choice == "2":
        return "oaep"

    raise ValueError("Invalid padding choice")


def choose_output_format():
    print("Choose output format:")
    print("1. hex")
    print("2. base64")

    choice = input("Enter choice: ").strip()

    if choice == "1":
        return "hex"
    if choice == "2":
        return "base64"

    raise ValueError("Invalid output format")


def bytes_to_output(data: bytes, output_format: str):
    if output_format == "hex":
        return data.hex()
    if output_format == "base64":
        return base64.b64encode(data).decode("utf-8")
    raise ValueError("Unsupported output format")


def output_to_bytes(data: str, input_format: str):
    if input_format == "hex":
        return bytes.fromhex(data)
    if input_format == "base64":
        return base64.b64decode(data.encode("utf-8"))
    raise ValueError("Unsupported input format")


def handle_generate_keys():
    try:
        
        bits = int(input("Enter key size (1024 / 2048 / 4096): ").strip())

        print("Generating keys...")
        public_key, private_key = generate_keypair(bits)

        print("\nPublic key info:")
        print(f"n (hex) = {format(public_key.n, 'x')}")
        print(f"e (hex) = {format(public_key.e, 'x')}")

        print("\nPrivate key info:")
        print(f"n (hex) = {format(private_key.n, 'x')}")
        print(f"d (hex) = {format(private_key.d, 'x')}")

        public_path = input("Enter path to save public key: ").strip()
        private_path = input("Enter path to save private key: ").strip()

        save_public_key(public_key, public_path)
        save_private_key(private_key, private_path)

        print("Keys generated and saved successfully.")

    except Exception as e:
        print(f"Error: {e}")


def handle_encrypt():
    try:
        public_key_path = input("Enter public key path: ").strip()
        public_key = load_public_key(public_key_path)

        padding_mode = choose_padding()
        output_format = choose_output_format()

        message = input("Enter message to encrypt: ")
        ciphertext = encrypt_bytes(message.encode("utf-8"), public_key, padding_mode)

        encoded_output = bytes_to_output(ciphertext, output_format)

        print(f"Ciphertext ({output_format}):")
        print(encoded_output)

        save_choice = input("Save ciphertext to file? (y/n): ").strip().lower()
        if save_choice == "y":
            file_path = input("Enter output file path: ").strip()

            if output_format == "hex":
                save_hex(ciphertext, file_path)
            elif output_format == "base64":
                save_base64(ciphertext, file_path)

            print(f"Ciphertext saved to: {file_path}")

    except Exception as e:
        print(f"Error: {e}")


def handle_decrypt():
    try:
        private_key_path = input("Enter private key path: ").strip()
        private_key = load_private_key(private_key_path)

        padding_mode = choose_padding()

        source_choice = input("Load ciphertext from file? (y/n): ").strip().lower()

        if source_choice == "y":
            input_format = choose_output_format()
            cipher_path = input("Enter ciphertext file path: ").strip()

            if input_format == "hex":
                ciphertext = load_hex(cipher_path)
            elif input_format == "base64":
                ciphertext = load_base64(cipher_path)
            else:
                raise ValueError("Unsupported input format")
        else:
            input_format = choose_output_format()
            encoded_ciphertext = input(f"Enter ciphertext {input_format}: ").strip()
            ciphertext = output_to_bytes(encoded_ciphertext, input_format)

        plaintext = decrypt_bytes(ciphertext, private_key, padding_mode)
        text = plaintext.decode("utf-8")

        print("Decrypted message:")
        print(text)

        save_choice = input("Save decrypted text to file? (y/n): ").strip().lower()
        if save_choice == "y":
            file_path = input("Enter output file path: ").strip()
            save_text(text, file_path)
            print(f"Decrypted text saved to: {file_path}")

    except Exception as e:
        print(f"Error: {e}")


def handle_hash_text():
    try:
        text = input("Enter text to hash: ")
        print("SHA-256:")
        print(sha256_text(text))
    except Exception as e:
        print(f"Error: {e}")


def handle_sign_message():
    try:
        private_key_path = input("Enter private key path: ").strip()
        private_key = load_private_key(private_key_path)

        output_format = choose_output_format()

        message = input("Enter message to sign: ")
        signature = sign_message(message.encode("utf-8"), private_key)

        encoded_output = bytes_to_output(signature, output_format)

        print(f"Signature ({output_format}):")
        print(encoded_output)

        save_choice = input("Save signature to file? (y/n): ").strip().lower()
        if save_choice == "y":
            file_path = input("Enter output file path: ").strip()

            if output_format == "hex":
                save_hex(signature, file_path)
            elif output_format == "base64":
                save_base64(signature, file_path)

            print(f"Signature saved to: {file_path}")

    except Exception as e:
        print(f"Error: {e}")


def handle_verify_signature():
    try:
        public_key_path = input("Enter public key path: ").strip()
        public_key = load_public_key(public_key_path)

        message = input("Enter original message: ").encode("utf-8")

        source_choice = input("Load signature from file? (y/n): ").strip().lower()

        if source_choice == "y":
            input_format = choose_output_format()
            signature_path = input("Enter signature file path: ").strip()

            if input_format == "hex":
                signature = load_hex(signature_path)
            elif input_format == "base64":
                signature = load_base64(signature_path)
            else:
                raise ValueError("Unsupported input format")
        else:
            input_format = choose_output_format()
            encoded_signature = input(f"Enter signature {input_format}: ").strip()
            signature = output_to_bytes(encoded_signature, input_format)

        is_valid = verify_message(message, signature, public_key)
        print("Signature is VALID." if is_valid else "Signature is INVALID.")

    except Exception as e:
        print(f"Error: {e}")


def handle_show_key_info():
    try:
        key_type = input("Show public or private key? (pub/priv): ").strip().lower()

        if key_type == "pub":
            path = input("Enter public key path: ").strip()
            key = load_public_key(path)
            print(f"n (hex) = {format(key.n, 'x')}")
            print(f"e (hex) = {format(key.e, 'x')}")
        elif key_type == "priv":
            path = input("Enter private key path: ").strip()
            key = load_private_key(path)
            print(f"n (hex) = {format(key.n, 'x')}")
            print(f"d (hex) = {format(key.d, 'x')}")
            print(f"p (hex) = {format(key.p, 'x')}")
            print(f"q (hex) = {format(key.q, 'x')}")
        else:
            print("Invalid choice.")

    except Exception as e:
        print(f"Error: {e}")


def handle_validate_keys():
    try:
        public_path = input("Enter public key path: ").strip()
        private_path = input("Enter private key path: ").strip()

        public_key = load_public_key(public_path)
        private_key = load_private_key(private_path)

        public_valid = validate_public_key(public_key)
        private_valid = validate_private_key(private_key)
        pair_valid = validate_key_pair(public_key, private_key)

        print("\nValidation results:")
        print(f"Public key valid: {'YES' if public_valid else 'NO'}")
        print(f"Private key valid: {'YES' if private_valid else 'NO'}")
        print(f"Key pair matches: {'YES' if pair_valid else 'NO'}")

        if pair_valid:
            print("Keys are valid.")
        else:
            print("Keys are invalid.")

    except Exception as e:
        print(f"Error: {e}")

def handle_save_text():
    try:
        text = input("Enter text: ")
        file_path = input("Enter file path: ").strip()
        save_text(text, file_path)
        print(f"Text saved to: {file_path}")
    except Exception as e:
        print(f"Error: {e}")


def handle_load_text():
    try:
        file_path = input("Enter file path: ").strip()
        print("Loaded text:")
        print(load_text(file_path))
    except Exception as e:
        print(f"Error: {e}")


def run_cli():
    while True:
        print_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            handle_generate_keys()
        elif choice == "2":
            handle_encrypt()
        elif choice == "3":
            handle_decrypt()
        elif choice == "4":
            handle_hash_text()
        elif choice == "5":
            handle_sign_message()
        elif choice == "6":
            handle_verify_signature()
        elif choice == "7":
            handle_show_key_info()
        elif choice == "8":
            handle_validate_keys()
        elif choice == "9":
            handle_save_text()
        elif choice == "10":
            handle_load_text()
        elif choice == "0":
            print("Exiting program.")
            break
        else:
            print("Invalid option. Try again.")