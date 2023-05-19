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
