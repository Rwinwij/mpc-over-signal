#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use allo_isolate::Isolate;
use async_ffi::{FfiFuture, FutureExt};
use std::os::raw::{c_char, c_uchar};
use core::slice;

use gg20_mpc::*;

use lazy_static::lazy_static;
use std::{ffi::CStr, io, os::raw};
use tokio::runtime::{Builder, Runtime};

lazy_static! {
    static ref RUNTIME: io::Result<Runtime> = Builder::new()
        .threaded_scheduler()
        .enable_all()
        .core_threads(4)
        .thread_name("flutterust")
        .build();
}

macro_rules! runtime {
    () => {
        match RUNTIME.as_ref() {
            Ok(rt) => rt,
            Err(_) => {
                return ();
            }
        }
    };
}

//MPC CONSTANTS
const THRESHOLD:u16 = 1;
const PARTIES:u16 = 3;

#[no_mangle]
pub extern "C" fn http_local_run() {
    let rt = runtime!();
    let http_task = async move {
        let result = gg20_mpc::http_local_run().await;
    }.into_ffi();
    rt.spawn(http_task);
}

#[no_mangle]
pub extern "C" fn wire_keygen(
    port_: i64,
    index: u16,
) {
    let rt = runtime!();
    let keygen_task = async move {
        let isolate = Isolate::new(port_);
        let (keyshare, pubkey_x_bigint, pubkey_y_bigint, pubkey_encoded_point) = gg20_mpc::keygen_run(index, port_).await.unwrap();
        isolate.post(keyshare); //private keyshare to be saved and encrypted on mobile using secure enslave
        isolate.post(pubkey_x_bigint); //BIG INT point X
        isolate.post(pubkey_y_bigint); //BIG INT point Y
        isolate.post(pubkey_encoded_point); //encoded ECPoint, need to be decoded on mobile using ECPoint constructor
    }.into_ffi();

    rt.spawn(keygen_task);
}

#[no_mangle]
pub extern "C" fn wire_presign(
    port_: i64,
    index: u16,
    local_key_vec: *const c_uchar,
    local_key_len: usize,
) {
    let rt = runtime!();
    let local_key = unsafe {slice::from_raw_parts(local_key_vec, local_key_len)};
    let local_key: Vec<u8> = Vec::from(local_key);

    let presign_task = async move {
        let isolate = Isolate::new(port_);
        let result = gg20_mpc::presign_run(index, local_key, port_).await;
        isolate.post(result);
    }.into_ffi();

    rt.spawn(presign_task);
}

#[no_mangle]
pub extern "C" fn wire_sign(
    port_: i64,
    index: u16,
    presign_vec: *const c_uchar,
    presign_len: usize,
    keccak256_payload: *const c_uchar,
    keccak256_payload_len: usize,
) {
    let rt = runtime!();
    let presign_share = unsafe {slice::from_raw_parts(presign_vec, presign_len)};
    let presign_share: Vec<u8> = Vec::from(presign_share);

    let hashed_message = unsafe {slice::from_raw_parts(keccak256_payload, keccak256_payload_len)};
    let hashed_message: Vec<u8> = Vec::from(hashed_message);

    let presign_task = async move {
        let isolate = Isolate::new(port_);
        let (sig_r_bigint, sig_s_bigint, sig_v) = gg20_mpc::sign_run(index, presign_share, hashed_message).await.unwrap();
        isolate.post(sig_r_bigint);
        isolate.post(sig_s_bigint);
        isolate.post(sig_v);
    }.into_ffi();

    rt.spawn(presign_task);
}
