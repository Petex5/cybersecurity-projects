# Hash Identifier

A command-line tool to identify and compute cryptographic hash types. Supports MD5, SHA-1, SHA-256, SHA-512, bcrypt, Argon2, and more.

## Features

- Identify unknown hashes by length and prefix
- Compute hashes for any input string
- Supports MD2, MD4, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, RIPEMD-160, BLAKE2s, BLAKE2b, bcrypt, Argon2
- Interactive CLI menu

## Requirements

- Python 3.6+

## Usage

```bash
python hash_identifier.py
```

## Supported Hash Types

| Length | Possible Types |
|--------|----------------|
| 32 | MD5, MD4, MD2 |
| 40 | SHA-1, RIPEMD-160 |
| 56 | SHA-224, SHA3-224 |
| 64 | SHA-256, SHA3-256, BLAKE2s |
| 96 | SHA-384, SHA3-384 |
| 128 | SHA-512, SHA3-512, BLAKE2b |
| Prefix `$2b$` | bcrypt |
| Prefix `$argon2` | Argon2 |

## Example

```
==================================================
        HASH IDENTIFIER TOOL
==================================================

Choose an option:
  1. Identify a hash
  2. Compute a hash
  3. Exit

Enter choice [1-3]: 1
Enter the hash to identify: 5d41402abc4b2a76b9719d911017c592

[+] Possible hash type(s):
    - MD5
    - MD4
    - MD2
```

## Author

Built as part of a cybersecurity portfolio project.