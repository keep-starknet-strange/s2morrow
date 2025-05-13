// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

use crate::blake2s::blake2s_32;
use crate::fors::{ForsSignature, fors_pk_from_sig};
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
pub fn verify_blake_128s(message: WordArray, sig: SphincsSignature) {
    let SphincsSignature { randomizer, pk_seed, pk_root, fors_sig } = sig;

    // Compute the extended message digest which is concatenation of `mhash || tree_idx ||
    // leaf_idx`.
    let digest = hash_message_128s(randomizer, pk_seed, pk_root, message, SPX_DGST_BYTES);

    // Split the digest into the message hash, tree address and leaf index.
    let XMessageDigest { mhash, tree_address, leaf_idx } = split_xdigest_128s(digest.span());

    // Compute FORS public key (root) from the signature.
    let fors_pk = fors_pk_from_sig(fors_sig, mhash);
}

/// Hash a message using Blake2s hash function.
/// Returns the extended message digest of size SPX_DGST_BYTES as a [WordArray].
/// NOTE: this is not a generic implementation, rather a shortcut for 128s.
fn hash_message_128s(
    randomizer: HashOutput,
    pk_seed: HashOutput,
    pk_root: HashOutput,
    message: WordArray,
    output_len: u32,
) -> WordArray {
    let mut data: Array<u32> = array![];
    data.append_span(randomizer.span());
    data.append_span(pk_seed.span());
    data.append_span(pk_root.span());

    let (msg_words, msg_last_word, _) = message.into_components();
    data.append_span(msg_words.span());
    data
        .append(
            msg_last_word,
        ); // message is expected to be zero padded if not a multiple of 4 bytes

    // Compute the seed for XOF.
    let seed = blake2s_32(data.span());

    let mut xof_data: Array<u32> = array![];
    xof_data.append_span(randomizer.span());
    xof_data.append_span(pk_seed.span());
    xof_data.append_span(seed.span());
    xof_data.append(0); // MGF1 counter = 0

    // Apply MGF1 to the seed.
    let mut buffer = blake2s_32(xof_data.span()).unbox().span();

    // Construct the digest from the extended output.
    // NOTE: we haven't cleared the LSB of the last word, has to be handled correctly.
    let last_word = *buffer.pop_back().unwrap();

    // Construct the digest from the first 7 words (28 bits) and add 2 bytes from the last word.
    let res = WordArrayTrait::new(buffer.into(), last_word, 2);
    assert(res.byte_len() == output_len, 'Invalid extended digest length');
    res
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
