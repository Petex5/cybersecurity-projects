import hashlib
import sys


def identify_hash(hash_string):
    """Identify the type of hash based on its length and character set."""
    hash_string = hash_string.strip()
    length = len(hash_string)

    # Check if it's a valid hex string
    try:
        int(hash_string, 16)
        is_hex = True
    except ValueError:
        is_hex = False

    hash_types = []

    if is_hex:
        if length == 32:
            hash_types.append("MD5")
            hash_types.append("MD4")
            hash_types.append("MD2")
        elif length == 40:
            hash_types.append("SHA-1")
            hash_types.append("SHA-0")
            hash_types.append("RIPEMD-160")
        elif length == 56:
            hash_types.append("SHA-224")
            hash_types.append("SHA3-224")
        elif length == 64:
            hash_types.append("SHA-256")
            hash_types.append("SHA3-256")
            hash_types.append("BLAKE2s")
        elif length == 96:
            hash_types.append("SHA-384")
            hash_types.append("SHA3-384")
        elif length == 128:
            hash_types.append("SHA-512")
            hash_types.append("SHA3-512")
            hash_types.append("BLAKE2b")
        elif length == 8:
            hash_types.append("CRC-32")
        elif length == 16:
            hash_types.append("CRC-64")
            hash_types.append("MD5 (partial)")
        else:
            hash_types.append(f"Unknown hex hash (length={length})")
    else:
        if hash_string.startswith("$2b$") or hash_string.startswith("$2a$"):
            hash_types.append("bcrypt")
        elif hash_string.startswith("$1$"):
            hash_types.append("MD5-crypt")
        elif hash_string.startswith("$5$"):
            hash_types.append("SHA-256-crypt")
        elif hash_string.startswith("$6$"):
            hash_types.append("SHA-512-crypt")
        elif hash_string.startswith("$pbkdf2"):
            hash_types.append("PBKDF2")
        elif hash_string.startswith("$argon2"):
            hash_types.append("Argon2")
        elif hash_string.startswith("$scrypt$"):
            hash_types.append("scrypt")
        else:
            hash_types.append("Unknown format")

    return hash_types


def compute_hash(text, algorithm):
    """Compute the hash of a given text using the specified algorithm."""
    algorithm = algorithm.lower()
    supported = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "sha3_256": hashlib.sha3_256,
        "sha3_512": hashlib.sha3_512,
        "blake2b": hashlib.blake2b,
        "blake2s": hashlib.blake2s,
    }
    if algorithm not in supported:
        print(f"[!] Unsupported algorithm '{algorithm}'.")
        print(f"    Supported: {', '.join(supported.keys())}")
        return None
    h = supported[algorithm](text.encode())
    return h.hexdigest()


def banner():
    print("=" * 50)
    print("         HASH IDENTIFIER TOOL")
    print("=" * 50)
    print()


def main():
    banner()
    print("Choose an option:")
    print("  1. Identify a hash")
    print("  2. Compute a hash")
    print("  3. Exit")
    print()

    while True:
        choice = input("Enter choice [1-3]: ").strip()

        if choice == "1":
            hash_input = input("\nEnter the hash to identify: ").strip()
            if not hash_input:
                print("[!] No input provided.\n")
                continue
            results = identify_hash(hash_input)
            print(f"\n[+] Possible hash type(s):")
            for r in results:
                print(f"    - {r}")
            print()

        elif choice == "2":
            text = input("\nEnter text to hash: ").strip()
            algo = input("Enter algorithm (md5/sha1/sha256/sha512/...): ").strip()
            result = compute_hash(text, algo)
            if result:
                print(f"\n[+] {algo.upper()} hash:")
                print(f"    {result}")
            print()

        elif choice == "3":
            print("[*] Exiting. Goodbye!")
            sys.exit(0)

        else:
            print("[!] Invalid choice. Please enter 1, 2, or 3.\n")


if __name__ == "__main__":
    main()
