// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

pub mod address;
pub mod fors;
pub mod hasher;
pub mod params_128s;
pub mod sha2;
pub mod sphincs;
pub mod word_array;
pub mod wots;
use crate::sphincs::SphincsSignature;
use crate::word_array::{WordArray, WordArrayTrait};

#[derive(Drop, Serde, Default)]
pub struct Args {
    /// Sphincs+ signature.
    pub sig: SphincsSignature,
    /// Message.
    pub message: WordArray,
}

#[executable]
fn main() {
    //let Args { sig, message } = args;

    let sig: SphincsSignature = Default::default();
    let message = WordArrayTrait::new(array![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], 0, 0);

    let mut serialized = array![];
    Serde::serialize(@sig, ref serialized);
    Serde::serialize(@message, ref serialized);

    //println!("serialized: {:?}", serialized);

    let res = sphincs::verify_128s(message.span(), sig);
    //assert(res, 'invalid signature');
}
