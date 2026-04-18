import time

from rsa_core import generate_keypair, encrypt_bytes, decrypt_bytes, sign_message, verify_message


def benchmark_key_generation(bits: int):
    start = time.perf_counter()
    generate_keypair(bits)
    end = time.perf_counter()
    return end - start


def benchmark_encryption(public_key, message: bytes, iterations: int = 100):
    start = time.perf_counter()

    for _ in range(iterations):
        encrypt_bytes(message, public_key, "pkcs1v15")

    end = time.perf_counter()
    total_time = end - start
    avg_time = total_time / iterations
    return total_time, avg_time


def benchmark_decryption(public_key, private_key, message: bytes, iterations: int = 100):
    ciphertexts = [encrypt_bytes(message, public_key, "pkcs1v15") for _ in range(iterations)]

    start = time.perf_counter()

    for ciphertext in ciphertexts:
        decrypt_bytes(ciphertext, private_key, "pkcs1v15")

    end = time.perf_counter()
    total_time = end - start
    avg_time = total_time / iterations
    return total_time, avg_time


def benchmark_signing(private_key, message: bytes, iterations: int = 100):
    start = time.perf_counter()

    for _ in range(iterations):
        sign_message(message, private_key)

    end = time.perf_counter()
    total_time = end - start
    avg_time = total_time / iterations
    return total_time, avg_time


def benchmark_verification(public_key, private_key, message: bytes, iterations: int = 100):
    signatures = [sign_message(message, private_key) for _ in range(iterations)]

    start = time.perf_counter()

    for signature in signatures:
        verify_message(message, signature, public_key)

    end = time.perf_counter()
    total_time = end - start
    avg_time = total_time / iterations
    return total_time, avg_time


def print_speed(name: str, total_time: float, avg_time: float, iterations: int):
    ops_per_second = iterations / total_time if total_time > 0 else 0

    print(f"{name}:")
    print(f"  Total time: {total_time:.6f} seconds")
    print(f"  Average time: {avg_time:.6f} seconds")
    print(f"  Speed: {ops_per_second:.2f} ops/second")
    print()


def main():
    message = b"Benchmark message for RSA"
    iterations = 100

    print("RSA BENCHMARKS\n")

    print("1. Key Generation Benchmark")
    t1024 = benchmark_key_generation(1024)
    print(f"1024-bit key generation: {t1024:.6f} seconds")

    t2048 = benchmark_key_generation(2048)
    print(f"2048-bit key generation: {t2048:.6f} seconds")
    print()

    print("2. Operation Benchmarks using 1024-bit key")
    public_key, private_key = generate_keypair(1024)

    enc_total, enc_avg = benchmark_encryption(public_key, message, iterations)
    print_speed("Encryption", enc_total, enc_avg, iterations)

    dec_total, dec_avg = benchmark_decryption(public_key, private_key, message, iterations)
    print_speed("Decryption", dec_total, dec_avg, iterations)

    sign_total, sign_avg = benchmark_signing(private_key, message, iterations)
    print_speed("Signature Generation", sign_total, sign_avg, iterations)

    verify_total, verify_avg = benchmark_verification(public_key, private_key, message, iterations)
    print_speed("Signature Verification", verify_total, verify_avg, iterations)


if __name__ == "__main__":
    main()