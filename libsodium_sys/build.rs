use std::{env, path::Path};

fn main() {
    pkg_config::Config::new()
        .atleast_version("1.0.18")
        .statik(true)
        .probe("libsodium")
        .unwrap();

    let bindings = bindgen::builder()
        .header("wrapper.h")
        .allowlist_function("sodium_init")
        .allowlist_function("crypto_generichash")
        .allowlist_function("crypto_generichash_init")
        .allowlist_function("crypto_generichash_update")
        .allowlist_function("crypto_generichash_final")
        .allowlist_var("^(crypto_generichash_(K|B).*)$")
        .allowlist_type("crypto_generichash_state")
        .generate()
        .unwrap();

    bindings
        .write_to_file(Path::new(env::var("OUT_DIR").unwrap().as_str()).join("ffi.rs"))
        .unwrap();
}
