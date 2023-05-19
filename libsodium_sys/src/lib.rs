#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
pub mod ffi {
    include!(concat!(env!("OUT_DIR"), "/ffi.rs"));
}
