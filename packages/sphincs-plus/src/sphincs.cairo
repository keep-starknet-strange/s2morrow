// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

use crate::fors::{ForsSignature, fors_pk_from_sig};
use crate::hasher::{hash_message_128s, initialize_hash_function};
use crate::params_128s::{HashOutput, SPX_DGST_BYTES};
use crate::word_array::{WordArray, WordArrayTrait, WordSpan, WordSpanTrait};

#[derive(Drop)]
pub struct SphincsSignature {
    pub randomizer: HashOutput,
    pub pk_seed: HashOutput,
    pub pk_root: HashOutput,
    pub fors_sig: ForsSignature,
}

#[derive(Drop)]
pub struct XMessageDigest {
    pub mhash: WordSpan,
    pub tree_address: u64,
    pub leaf_idx: u16,
}

/// Verify a signature for Sphincs+ instantiated with Blake2s with 128s parameters.
pub fn verify_blake_128s(message: WordSpan, sig: SphincsSignature) {
    let SphincsSignature { randomizer, pk_seed, pk_root, fors_sig } = sig;

    // Seed the hash function state.
    let ctx = initialize_hash_function(pk_seed);

    // Compute the extended message digest which is concatenation of `mhash || tree_idx ||
    // leaf_idx`.
    let digest = hash_message_128s(randomizer, pk_seed, pk_root, message, SPX_DGST_BYTES);

    // Split the digest into the message hash, tree address and leaf index.
    let XMessageDigest { mhash, tree_address, leaf_idx } = split_xdigest_128s(digest.span());

    // Compute FORS public key (root) from the signature.
    let fors_pk = fors_pk_from_sig(ctx, fors_sig, mhash, Default::default());
}

/// Split the extended message digest into the message hash, tree address and leaf index.
/// NOTE: this is not a generic implementation, rather a shortcut for 128s.
fn split_xdigest_128s(mut digest: WordSpan) -> XMessageDigest {
    let (mut words, last_word, _) = digest.into_components();

    // Lead index is the 9 LSB of the higher 2 bytes of the last word.
    let leaf_idx = (last_word / 0x10000) % 0x200;
    let leaf_idx: u16 = leaf_idx.try_into().expect('u32 -> u16 cast failed');

    // Tree address is the 54 LSB of the last two words.
    let lo = *words.pop_back().unwrap();
    let hi = *words.pop_back().unwrap();
    let tree_address = (hi.into() % 0x7fffff) * 0x100000000 + lo.into();

    // Message hash is the remaining 21 bytes.
    // NOTE: we haven't cleared the LSB of the last word, has to be handled correctly.
    let mhash = WordSpanTrait::new(words.into(), hi, 1);

    XMessageDigest { mhash, tree_address, leaf_idx }
}
