//! A safe, oxidized wrapper for libsodium.
//!
//! # Hashing a message
//! ```rust
//! use tablesalt::sodium;
//!
//! let s = sodium::Sodium::new();
//! let hash = s.crypto_generichash(b"Some message", None, 32);
//!
//! println!("blake2b hash: {}", hex::encode(&hash));
//! ```
//!
//! # Hashing a multi-part message.
//! ```rust
//! use tablesalt::sodium;
//!     
//! let s = sodium::Sodium::new();
//! let mut state = s.crypto_generichash_init(None, 32);
//! state.update(b"Some ");
//! state.update(b"message");
//! let hash = state.finalize();
//!
//! println!("blake2b hash: {}", hex::encode(&hash));
//! ```

pub mod sodium;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sodium::SecretStreamTag;

    #[test]
    fn test_init_sodium() {
        let _ = sodium::Sodium::new();
    }

    #[test]
    fn test_crypto_generichash() {
        let s = sodium::Sodium::new();
        let hash = s.crypto_generichash(b"Some message!", None, 32);
        assert_eq!(
            hex::encode(hash.as_slice()),
            "1e28ae8e58437cedd2bf3cad27d9d7c5ab454014d39ed893c25bc2ae2807b031"
        );
    }

    #[test]
    fn test_crypto_generichash_with_key() {
        let hash = sodium::Sodium::new().crypto_generichash(b"Some message!", Some(b"key"), 64);
        assert_eq!(
            hex::encode(hash),
            concat!(
                "6368da700e596f77afc013867dd108a9f442c4d56b7a55d6cd4943303aef461",
                "9f0148de2ae7948a901a1147c57e3ec0faf69bf021e3e50a537462760fbca3615"
            )
        );
    }

    #[test]
    fn test_crypto_generichash_multipart() {
        let s = sodium::Sodium::new();
        let mut state = s.crypto_generichash_init(None, 32);
        state.update(b"a");
        state.update(b"b");
        state.update(b"c");
        let h1 = state.finalize();
        let h2 = s.crypto_generichash(b"abc", None, 32);
        assert_eq!(h1, h2);
    }

    #[test]
    #[should_panic]
    fn test_hash_len_min() {
        let s = sodium::Sodium::new();
        let _ = s.crypto_generichash(b"Some message!", None, 15);
    }

    #[test]
    #[should_panic]
    fn test_hash_len_max() {
        let s = sodium::Sodium::new();
        let _ = s.crypto_generichash(b"Some message!", None, 65);
    }

    #[test]
    #[should_panic]
    fn test_hash_keylen_max() {
        let s = sodium::Sodium::new();
        let _ = s.crypto_generichash(b"Some message!", Some(&[0u8; 65]), 32);
    }

    #[test]
    fn test_secretstream_keygen() {
        let s = sodium::Sodium::new();
        let key = s.crypto_secretstream_keygen();

        println!("Generated Key: {}", hex::encode(&key));

        // Key will be dropped here anyway, but we're
        // trying to bey explicit about the fact that the key bytes
        // should be deallocated by Rust.
        drop(key);
    }

    #[test]
    fn test_thread_safety() {
        let s = sodium::Sodium::new();
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let handle = std::thread::spawn(move || {
            let hash = s.crypto_generichash(b"Some message!", None, 32);
            tx.send(hash).unwrap();
        });

        let hash = rx.recv().unwrap();
        handle.join().unwrap();
        assert_eq!(
            hex::encode(hash.as_slice()),
            "1e28ae8e58437cedd2bf3cad27d9d7c5ab454014d39ed893c25bc2ae2807b031"
        );
    }

    #[test]
    fn test_secretstream() {
        let s = sodium::Sodium::new();
        let key = s.crypto_secretstream_keygen();
        let mut state = s.crypto_secretstream_init_push(key.clone());
        let c1 = state.push(b"Hello, ", SecretStreamTag::Message);
        let c2 = state.push(b"World!", SecretStreamTag::Final);

        println!("Ciphertext 1: {}", hex::encode(&c1));
        println!("Ciphertext 2: {}", hex::encode(&c2));

        let mut pull = s
            .crypto_secretstream_init_pull(state.header().clone(), key)
            .unwrap();
        let (msg1, tag1) = pull.pull(&c1);
        let (msg2, tag2) = pull.pull(&c2);

        println!("Message 1: {}", String::from_utf8(msg1.clone()).unwrap());
        println!("Message 2: {}", String::from_utf8(msg2.clone()).unwrap());

        assert_eq!(msg1, b"Hello, ");
        assert_eq!(msg2, b"World!");
        assert_eq!(tag1, SecretStreamTag::Message);
        assert_eq!(tag2, SecretStreamTag::Final);
    }

    #[test]
    fn test_generate_master_key() {
        let s = sodium::Sodium::new();
        let key = s.crypto_kdf_keygen(b"Examples");
        println!("Key: {}", hex::encode(key));
    }

    #[test]
    fn test_generate_subkey() {
        let s = sodium::Sodium::new();
        let key = s.crypto_kdf_keygen(b"Examples");
        println!("Master Key: {}", hex::encode(&key));

        let s1 = key.derive_subkey(1, 16);
        let s2 = key.derive_subkey(2, 32);
        let s3 = key.derive_subkey(3, 64);

        assert_eq!(s1.len(), 16);
        assert_eq!(s2.len(), 32);
        assert_eq!(s3.len(), 64);
    }

    #[test]
    #[should_panic]
    fn test_subkey_too_short() {
        let s = sodium::Sodium::new();
        let key = s.crypto_kdf_keygen(b"Examples");
        println!("Master Key: {}", hex::encode(&key));

        let _ = key.derive_subkey(1, 15);
    }

    #[test]
    #[should_panic]
    fn test_subkey_too_long() {
        let s = sodium::Sodium::new();
        let key = s.crypto_kdf_keygen(b"Examples");
        println!("Master Key: {}", hex::encode(&key));

        let _ = key.derive_subkey(1, 65);
    }
}
