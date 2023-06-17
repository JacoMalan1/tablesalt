# TableSalt

![codecov](https://codecov.io/gh/JacoMalan1/tablesalt/branch/dev/graph/badge.svg?token=48MT5VFW97)
![test](https://github.com/JacoMalan1/tablesalt/actions/workflows/test.yml/badge.svg)
![safety](https://github.com/JacoMalan1/tablesalt/actions/workflows/safety.yml/badge.svg)
![schedule](https://github.com/JacoMalan1/tablesalt/actions/workflows/scheduled.yml/badge.svg)
![check](https://github.com/JacoMalan1/tablesalt/actions/workflows/check.yml/badge.svg)

## Description
TableSalt is a safe, oxidized wrapper for libsodium.

## Usage
To use tablesalt, add start by adding it as a dependency in your `Cargo.toml` file.
```toml
[dependencies]
tablesalt = "0.3.1"
```

## Hashing
Currently, TableSalt only provides libsodium's crypto_generichash API.

### Hashing a message
The following example shows how to hash a simple message. The code here uses the crate
`hex` to encode the hash, which is a `Vec<u8>` into a hexadecimal string.
```rust
use tablesalt::sodium;

fn main() {
    let s = sodium::Sodium::new();
    let hash = s.crypto_generichash(b"Some message", None, 32);

    println!("blake2b hash: {}", hex::encode(&hash));
}
```

### Hashing a multi-part message
```rust
use tablesalt::sodium;

fn main() {
    let s = sodium::Sodium::new();
    let mut state = s.crypto_generichash_init(None, 32);
    state.update(b"Some ");
    state.update(b"message");
    let hash = state.finalize();

    println!("blake2b hash: {}", hex::encode(&hash));
}
```
