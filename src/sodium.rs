use std::{marker::PhantomData, mem::MaybeUninit, rc::Rc};

use libsodium_sys::ffi;

#[non_exhaustive]
#[derive(Copy, Clone, Debug)]
/// A handle to the libsodium api
///
/// # Thread Safety
/// This struct implements is both `Send` and `Sync`.
/// This is because we know that if there exists at least one
/// reference to one of these objects, libsodium has been initialized
/// and may be used.
pub struct Sodium {
    phantom: PhantomData<()>,
}

#[allow(clippy::new_without_default)]
impl Sodium {
    /// Initializes libsodium
    /// This function may be called multiple times and from different threads.
    ///
    /// # Returns
    /// A `Sodium` object. This type is both `Send` and `Sync`
    pub fn new() -> Self {
        // SAFETY: We are allowed to init sodium multiple times and from
        // different threads. It is not supposed to crash and will always return
        // a value.
        if unsafe { ffi::sodium_init() } < 0 {
            panic!("Couldn't initialize libsodium!");
        }

        Self {
            phantom: PhantomData,
        }
    }

    /// This function takes in a message and a key and returns a hash of the message
    /// with the key.
    ///
    /// # Returns
    /// A `Vec<u8>` containing the hashed bytes for this message.
    ///
    /// # Panics
    /// This function will panic if the passed in hash_len is less than
    /// `libsodium_sys::ffi::crypto_generichash_BYTES_MIN` or greater than `libsodium_sys::ffi::crypto_generichash_BYTES_MAX`.
    /// It will also panic if the length of the key is greater than
    /// `libsodium_sys::ffi::crypto_generichash_KEYBYTES_MAX`
    pub fn crypto_generichash(self, msg: &[u8], key: Option<&[u8]>, hash_len: usize) -> Vec<u8> {
        // Panic if any of the buffer sizes is outside the allowed range
        assert!(hash_len >= usize::try_from(ffi::crypto_generichash_BYTES_MIN).unwrap());
        assert!(hash_len <= usize::try_from(ffi::crypto_generichash_BYTES_MAX).unwrap());
        assert!(
            key.unwrap_or(b"").len()
                <= usize::try_from(ffi::crypto_generichash_KEYBYTES_MAX).unwrap()
        );

        let mut buf = Vec::<u8>::with_capacity(hash_len);

        // SAFETY: Since we have a self, libsodium must be initialized, so we can safely
        // call any libsodium functions.
        unsafe {
            ffi::crypto_generichash(
                buf.as_mut_ptr(),
                hash_len,
                msg.as_ref().as_ptr(),
                msg.as_ref().len() as u64,
                key.unwrap_or(b"").as_ptr(),
                key.unwrap_or(b"").len(),
            )
        };

        // SAFETY: The crypto_generichash function will write HASH_SIZE bytes
        // into the buffer, so we can assume that the memory contained there is initialized.
        unsafe {
            buf.set_len(hash_len);
        }

        buf
    }

    /// Creates a new multi-part crypto_generichash state.
    ///
    /// # Panics
    /// This function will panic if the passed in hash_len is less than
    /// `libsodium_sys::ffi::crypto_generichash_BYTES_MIN` or greater than `libsodium_sys::ffi::crypto_generichash_BYTES_MAX`.
    /// It will also panic if the length of the key is greater than
    /// `libsodium_sys::ffi::crypto_generichash_KEYBYTES_MAX`
    pub fn crypto_generichash_init(
        self,
        key: Option<&[u8]>,
        hash_len: usize,
    ) -> CryptoGenericHashState {
        // Panic if any of the buffer sizes is outside the allowed range
        assert!(hash_len >= usize::try_from(ffi::crypto_generichash_BYTES_MIN).unwrap());
        assert!(hash_len <= usize::try_from(ffi::crypto_generichash_BYTES_MAX).unwrap());
        assert!(
            key.unwrap_or(b"").len()
                <= usize::try_from(ffi::crypto_generichash_KEYBYTES_MAX).unwrap()
        );

        let mut state =
            Box::<MaybeUninit<ffi::crypto_generichash_state>>::new(MaybeUninit::uninit());

        // SAFETY: crypto_generichash_init should initialize state correctly.
        // Also, the buffer sizes have already been checked and must be valid.
        unsafe {
            ffi::crypto_generichash_init(
                state.as_mut_ptr(),
                key.unwrap_or(b"").as_ptr(),
                key.unwrap_or(b"").len(),
                hash_len,
            )
        };

        CryptoGenericHashState {
            hash_len,
            internal: state,
            phantom: PhantomData,
        }
    }
}

pub struct CryptoGenericHashState {
    hash_len: usize,
    internal: Box<MaybeUninit<ffi::crypto_generichash_state>>,
    phantom: PhantomData<Rc<u8>>,
}

impl CryptoGenericHashState {
    /// Updates the hash with some input data.
    pub fn update(&mut self, input: &[u8]) {
        // SAFETY: Since we have an exclusive reference to self, we must have
        // initialized the state and so it is safe to pass a pointer to it into
        // crypto_generichash_update. Also, if the input length doesn't fit into u64, we will
        // panic before even calling the function.
        unsafe {
            ffi::crypto_generichash_update(
                self.internal.as_mut_ptr(),
                input.as_ptr(),
                input.len().try_into().unwrap(),
            )
        };
    }

    /// Finalizes the hash, consuming self and returning a `Vec<u8>`
    /// containing the output bytes.
    pub fn finalize(mut self) -> Vec<u8> {
        let mut buf = Vec::<u8>::with_capacity(self.hash_len);

        // SAFETY: Since we have an exclusive reference to self, we must have
        // initialized the state and so it is safe to pass a pointer to it into
        // crypto_generichash_final. Also, the buffer is allocated with a length of hash_len. We
        // also know that crypto_generichash_final will write hash_len bytes into buf.
        // Therefore it is safe to set it's length to hash_len.
        unsafe {
            ffi::crypto_generichash_final(
                self.internal.as_mut_ptr(),
                buf.as_mut_ptr(),
                self.hash_len,
            );
            buf.set_len(self.hash_len);
        };

        buf
    }
}
