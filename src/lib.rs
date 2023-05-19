pub mod sodium;

#[cfg(test)]
mod tests {
    use super::*;

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
            hex::encode(&hash),
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
}
