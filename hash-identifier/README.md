# Hash Identifier

A Python command-line tool to **identify** hash types and **compute** hashes from text.

## Features

- Identify hash types by length and format (MD5, SHA-1, SHA-256, SHA-512, bcrypt, Argon2, and more)
- Compute hashes using multiple algorithms (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3, BLAKE2)
- Interactive CLI menu
- No external dependencies — uses Python's built-in `hashlib`

## Usage

```bash
python hash_identifier.py
```

### Menu Options

```
1. Identify a hash  — paste a hash to detect its type
2. Compute a hash   — enter text and choose an algorithm
3. Exit
```

## Supported Hash Types (Identification)

| Length | Possible Types |
|--------|----------------|
| 32     | MD5, MD4, MD2  |
| 40     | SHA-1, RIPEMD-160 |
| 56     | SHA-224, SHA3-224 |
| 64     | SHA-256, SHA3-256, BLAKE2s |
| 96     | SHA-384, SHA3-384 |
| 128    | SHA-512, SHA3-512, BLAKE2b |
| Prefix `$2b$` | bcrypt |
| Prefix `$argon2` | Argon2 |

## Requirements

- Python 3.6+

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
