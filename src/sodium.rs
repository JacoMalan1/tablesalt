use libsodium_sys::ffi;

#[non_exhaustive]
#[derive(Copy, Clone, Debug)]
pub struct Sodium {
    _priv: u8,
}

#[allow(clippy::new_without_default)]
impl Sodium {
    /// Initializes libsodium
    pub fn new() -> Self {
        // SAFETY: We are allowed to init sodium multiple times and from
        // different threads. It is not supposed to crash and will always return
        // a value.
        if unsafe { ffi::sodium_init() } < 0 {
            panic!("Couldn't initialize libsodium!");
        }

        Self { _priv: 0 }
    }

    /// This function takes in a message and a key and returns a hash of the message
    /// with the key.
    pub fn crypto_generichash<const HASH_SIZE: usize>(
        self,
        msg: impl AsRef<[u8]>,
        key: impl AsRef<[u8]>,
    ) -> Box<dyn AsRef<[u8]>> {
        // Panic if any of the buffer sizes is outside the allowed range
        assert!(HASH_SIZE >= usize::try_from(ffi::crypto_generichash_BYTES_MIN).unwrap());
        assert!(HASH_SIZE <= usize::try_from(ffi::crypto_generichash_BYTES_MAX).unwrap());
        assert!(
            key.as_ref().len() <= usize::try_from(ffi::crypto_generichash_KEYBYTES_MAX).unwrap()
        );

        let mut buf = Vec::<u8>::with_capacity(HASH_SIZE);

        // SAFETY: Since we have a self, libsodium must be initialized, so we can safely
        // call any libsodium functions.
        unsafe {
            ffi::crypto_generichash(
                buf.as_mut_ptr(),
                HASH_SIZE,
                msg.as_ref().as_ptr(),
                msg.as_ref().len() as u64,
                key.as_ref().as_ptr(),
                key.as_ref().len(),
            )
        };

        // SAFETY: The crypto_generichash function will write HASH_SIZE bytes
        // into the buffer, so we can assume that the memory contained there is initialized.
        unsafe {
            buf.set_len(HASH_SIZE);
        }

        Box::new(buf)
    }
}
