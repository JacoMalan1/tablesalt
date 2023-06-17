use libsodium_sys as ffi;
use std::{marker::PhantomData, mem::MaybeUninit, rc::Rc};

#[non_exhaustive]
#[derive(Copy, Clone, Debug)]
/// A handle to the libsodium api
///
/// # Thread Safety
/// This struct implements is both [`Send`] and [`Sync`].
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
    /// A [`Sodium`] object. This type is both [`Send`] and [`Sync`]
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
    /// A [`Vec<u8>`] containing the hashed bytes for this message.
    ///
    /// # Panics
    /// This function will panic if the passed in hash_len is less than
    /// [`ffi::crypto_generichash_BYTES_MIN`] or greater than [`ffi::crypto_generichash_BYTES_MAX`].
    /// It will also panic if the length of the key is greater than
    /// [`ffi::crypto_generichash_KEYBYTES_MAX`]
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
    /// [`ffi::crypto_generichash_BYTES_MIN`] or greater than [`ffi::crypto_generichash_BYTES_MAX`].
    /// It will also panic if the length of the key is greater than
    /// [`ffi::crypto_generichash_KEYBYTES_MAX`]
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

    /// This function generates a secret key.
    ///
    /// # Returns
    /// Returns a [`CryptoSecretStreamKey`].
    pub fn crypto_secretstream_keygen(self) -> CryptoSecretStreamKey {
        let mut buffer = Vec::<MaybeUninit<u8>>::with_capacity(
            ffi::crypto_secretstream_xchacha20poly1305_KEYBYTES as usize,
        );

        // SAFETY: crypto_secretstream_..._keygen should initialize the buffer.
        // It is therefore safe to set it to the length of crypto_secretstream_..._KEYBYTES
        unsafe {
            ffi::crypto_secretstream_xchacha20poly1305_keygen(buffer.as_mut_ptr() as *mut u8);
            buffer.set_len(ffi::crypto_secretstream_xchacha20poly1305_KEYBYTES as usize);
        };

        // SAFETY: See safety for the above unsafe block.
        // (This buffer should be initialized)
        let buffer = buffer.iter().map(|b| unsafe { b.assume_init() }).collect();
        CryptoSecretStreamKey::new(buffer)
    }

    /// Initializes an encryption stream.
    ///
    /// # Example
    /// ```rust
    /// use tablesalt::sodium::{self, SecretStreamTag};
    ///
    /// let s = sodium::Sodium::new();
    /// let key = s.crypto_secretstream_keygen();
    /// let mut stream = s.crypto_secretstream_init_push(key);
    /// let ciphertext1 = stream.push(b"Hello, ", SecretStreamTag::Message);
    /// let ciphertext2 = stream.push(b"World!", SecretStreamTag::Final);
    ///
    /// println!("Ciphertext 1: {}", hex::encode(&ciphertext1));
    /// println!("Ciphertext 2: {}", hex::encode(&ciphertext2));
    /// ```
    pub fn crypto_secretstream_init_push(
        self,
        key: CryptoSecretStreamKey,
    ) -> CryptoSecretStreamPush {
        let mut state = Box::<MaybeUninit<ffi::crypto_secretstream_xchacha20poly1305_state>>::new(
            MaybeUninit::uninit(),
        );

        let mut header = Vec::<MaybeUninit<u8>>::with_capacity(
            ffi::crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize,
        );

        // SAFETY: crypto_secretstream_..._init_push should initialize the state and
        // the header. We know it will push the specified number of bytes into
        // the vector, so it is safe to set it's length to that.
        let header = unsafe {
            ffi::crypto_secretstream_xchacha20poly1305_init_push(
                state.as_mut_ptr(),
                header.as_mut_ptr() as *mut u8,
                key._buffer.as_ptr(),
            );
            header.set_len(ffi::crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize);
            header.iter().map(|b| b.assume_init()).collect()
        };

        CryptoSecretStreamPush {
            internal: state,
            header,
            _phantom: PhantomData,
        }
    }

    /// Initializes a decryption stream.
    ///
    /// # Params
    ///  - `header`: [`Vec<u8>`], the header generated by the encryption function.
    ///  - `key`: [`CryptoSecretStreamKey`], the decryption key.
    ///
    /// # Returns
    /// A result containing the [`CryptoSecretStreamPull`] or an [`InvalidHeaderError`] if the
    /// header was invalid.
    pub fn crypto_secretstream_init_pull(
        self,
        header: Vec<u8>,
        key: CryptoSecretStreamKey,
    ) -> Result<CryptoSecretStreamPull, InvalidHeaderError> {
        let mut state = Box::<MaybeUninit<ffi::crypto_secretstream_xchacha20poly1305_state>>::new(
            MaybeUninit::uninit(),
        );

        if -1
            == (unsafe {
                ffi::crypto_secretstream_xchacha20poly1305_init_pull(
                    state.as_mut_ptr(),
                    header.as_ptr(),
                    key._buffer.as_ptr(),
                )
            })
        {
            return Err(InvalidHeaderError {});
        }

        Ok(CryptoSecretStreamPull {
            internal: state,
            _phantom: PhantomData,
        })
    }

    /// Generates a master key for use in crypto_kdf_derive_from_key.
    ///
    /// # Returns
    /// A [`Vec<u8>`] containing the generated master key.
    pub fn crypto_kdf_keygen(
        self,
        context: &[u8; ffi::crypto_kdf_CONTEXTBYTES as usize],
    ) -> KdfMasterKey {
        let mut buffer = MaybeUninit::new([0u8; ffi::crypto_kdf_KEYBYTES as usize]);

        // SAFETY: We know that crypto_kdf_keygen will write crypto_kdf_KEYBYTES into
        // `buffer`, so it is safe to assume it is initialized.
        let buffer = unsafe {
            ffi::crypto_kdf_keygen(buffer.as_mut_ptr() as *mut u8);
            buffer.assume_init()
        };

        KdfMasterKey {
            internal: buffer,
            context: *context,
        }
    }
}

#[derive(Copy, Clone)]
pub struct KdfMasterKey {
    internal: [u8; ffi::crypto_kdf_KEYBYTES as usize],
    context: [u8; ffi::crypto_kdf_CONTEXTBYTES as usize],
}

impl KdfMasterKey {
    /// Derives a subkey from a master key.
    ///
    /// # Panics
    ///  - Panics if the provided `subkey_len` is not in the range (16..=64).
    ///
    /// # Returns
    /// A [`Vec<u8>`] containing the derived subkey.
    pub fn derive_subkey(&self, subkey_id: u64, subkey_len: usize) -> Vec<u8> {
        assert!((16..=64).contains(&subkey_len));

        let mut result = Vec::<u8>::with_capacity(subkey_len);

        // SAFETY: See safety for Sodium::crypto_kdf_keygen.
        unsafe {
            ffi::crypto_kdf_derive_from_key(
                result.as_mut_ptr(),
                subkey_len,
                subkey_id,
                self.context.as_ptr() as *const i8,
                self.internal.as_ptr(),
            );
            result.set_len(subkey_len);
        }

        result
    }
}

impl AsRef<[u8]> for KdfMasterKey {
    fn as_ref(&self) -> &[u8] {
        &self.internal
    }
}

/// An error indicating that a provided decryption header
/// was invalid.
#[derive(Debug, Clone, Copy)]
pub struct InvalidHeaderError {}

/// A key for encrypting and decrypting streams of data.
#[derive(Debug, Clone)]
pub struct CryptoSecretStreamKey {
    _buffer: Vec<u8>,
}

impl CryptoSecretStreamKey {
    fn new(buffer: Vec<u8>) -> Self {
        Self { _buffer: buffer }
    }
}

impl AsRef<[u8]> for CryptoSecretStreamKey {
    fn as_ref(&self) -> &[u8] {
        &self._buffer
    }
}

/// A multi-part blake2b hash stream.
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

    /// Finalizes the hash, consuming self and returning a [`Vec<u8>`]
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

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SecretStreamTag {
    Message = 0,
    Push = 1,
    Rekey = 2,
    Final = 3,
}

impl From<u8> for SecretStreamTag {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Message,
            1 => Self::Push,
            2 => Self::Rekey,
            3 => Self::Final,
            _ => panic!("Invalid stream tag!"),
        }
    }
}

/// An encrypted stream.
pub struct CryptoSecretStreamPush {
    internal: Box<MaybeUninit<ffi::crypto_secretstream_xchacha20poly1305_state>>,
    header: Vec<u8>,
    _phantom: PhantomData<Rc<u8>>,
}

impl CryptoSecretStreamPush {
    /// Pushes a chunk of message data with a tag.
    ///
    /// # Panics
    /// Panics if the length of `msg` is greater than
    /// [`ffi::crypto_secretstream_xchacha20poly1305_messagebytes_max()`]
    ///
    /// # Returns
    /// A [`Vec<u8>`] containing the ciphertext for the provided chunk of
    /// message data.
    pub fn push(&mut self, msg: &[u8], tag: SecretStreamTag) -> Vec<u8> {
        // SAFETY: Since we have a &mut self, there must exist a Sodium somewhere so libsodium
        // has been initialized
        assert!(
            msg.len() <= unsafe { ffi::crypto_secretstream_xchacha20poly1305_messagebytes_max() }
        );

        let mut ciphertext = Vec::<MaybeUninit<u8>>::with_capacity(
            msg.len() + ffi::crypto_secretstream_xchacha20poly1305_ABYTES as usize,
        );

        // SAFETY: We know that this function should produce msg.len() + ...ABYTES of data.
        // It is therefore safe to assume that ciphertext is fully initialized.
        unsafe {
            ffi::crypto_secretstream_xchacha20poly1305_push(
                self.internal.as_mut_ptr(),
                ciphertext.as_mut_ptr() as *mut u8,
                std::ptr::null_mut(),
                msg.as_ptr(),
                msg.len().try_into().unwrap(),
                std::ptr::null(),
                0,
                tag as u8,
            );
            ciphertext
                .set_len(msg.len() + ffi::crypto_secretstream_xchacha20poly1305_ABYTES as usize);
            ciphertext.iter().map(|b| b.assume_init()).collect()
        }
    }

    /// Returns a reference to the header for this encryption stream.
    pub fn header(&self) -> &Vec<u8> {
        &self.header
    }
}

/// A decryption stream.
pub struct CryptoSecretStreamPull {
    internal: Box<MaybeUninit<ffi::crypto_secretstream_xchacha20poly1305_state>>,
    _phantom: PhantomData<Rc<u8>>,
}

impl CryptoSecretStreamPull {
    /// Decrypts a block of ciphertext into plaintext and a tag.
    ///
    /// # Returns
    /// A tuple `(Vec<u8>, SecretStreamTag)` where the first element is the plaintext, and
    /// the second element is the associated tag.
    pub fn pull(&mut self, ciphertext: &[u8]) -> (Vec<u8>, SecretStreamTag) {
        let mut msg = Vec::<MaybeUninit<u8>>::with_capacity(
            ciphertext.len() - ffi::crypto_secretstream_xchacha20poly1305_ABYTES as usize,
        );

        let mut tag = 0u8;

        unsafe {
            ffi::crypto_secretstream_xchacha20poly1305_pull(
                self.internal.as_mut_ptr(),
                msg.as_mut_ptr() as *mut u8,
                std::ptr::null_mut(),
                std::ptr::addr_of_mut!(tag),
                ciphertext.as_ptr(),
                ciphertext.len().try_into().unwrap(),
                std::ptr::null(),
                0,
            );

            msg.set_len(
                ciphertext.len() - ffi::crypto_secretstream_xchacha20poly1305_ABYTES as usize,
            );
            (
                msg.iter().map(|b| b.assume_init()).collect(),
                SecretStreamTag::from(tag),
            )
        }
    }
}
