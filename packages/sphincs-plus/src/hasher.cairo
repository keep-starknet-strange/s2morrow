// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

use crate::params_128s::HashOutput;
use crate::sha2::{Sha256State, sha256_inc_finalize, sha256_inc_init, sha256_inc_update};
use crate::word_array::{WordArray, WordArrayTrait, WordSpan, WordSpanTrait};

#[derive(Drop, Copy, Default, Debug)]
pub struct SpxCtx {
    pub state_seeded: Sha256State,
}

/// Absorb the constant pub_seed using one round of the compression function
/// This initializes state_seeded and state_seeded_512, which can then be
/// reused input thash
pub fn initialize_hash_function(pk_seed: HashOutput) -> SpxCtx {
    let mut data = pk_seed.span().into();
    data.append_span(array![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].span());

    let mut state: Sha256State = Default::default();
    sha256_inc_init(ref state);
    sha256_inc_update(ref state, data.span());

    SpxCtx { state_seeded: state }
}

/// Compute a truncated hash of the data.
pub fn thash_128s(ctx: SpxCtx, mut data: WordSpan) -> HashOutput {
    let (input, last_word, last_word_len) = data.into_components();
    let [d0, d1, d2, d3, _, _, _, _] = sha256_inc_finalize(
        ctx.state_seeded, input.into(), last_word, last_word_len,
    );
    [d0, d1, d2, d3]
}

/// Hash a message using selected hash function.
/// Returns the extended message digest of size SPX_DGST_BYTES as a [WordArray].
/// NOTE: this is not a generic implementation, rather a shortcut for 128s.
pub fn hash_message_128s(
    randomizer: HashOutput,
    pk_seed: HashOutput,
    pk_root: HashOutput,
    message: WordSpan,
    output_len: u32,
) -> WordArray {
    Default::default()
    // let mut data: Array<u32> = array![];
// data.append_span(randomizer.span());
// data.append_span(pk_seed.span());
// data.append_span(pk_root.span());

    // let (msg_words, msg_last_word, msg_last_word_len) = message.into_components();
// data.append_span(msg_words);

    // // Compute the seed for XOF.
// let seed = blake2s_32(WordSpanTrait::new(data.span(), msg_last_word, msg_last_word_len));

    // let mut xof_data: Array<u32> = array![];
// xof_data.append_span(randomizer.span());
// xof_data.append_span(pk_seed.span());
// xof_data.append_span(seed.span());
// xof_data.append(0); // MGF1 counter = 0

    // // Apply MGF1 to the seed.
// let mut buffer = blake2s_32(WordSpanTrait::new(xof_data.span(), 0, 0)).unbox().span();

    // // Construct the digest from the extended output.
// // NOTE: we haven't cleared the LSB of the last word, has to be handled correctly.
// let last_word = *buffer.pop_back().unwrap();

    // // Construct the digest from the first 7 words (28 bits) and add 2 bytes from the last word.
// let res = WordArrayTrait::new(buffer.into(), last_word, 2);
// assert(res.byte_len() == output_len, 'Invalid extended digest length');
// res
}

#[cfg(test)]
mod tests {
    use crate::word_array::WordSpanTrait;
    use crate::word_array::hex::words_from_hex;
    use super::*;

    #[test]
    fn test_thash_128s() {
        let mut data = words_from_hex("00002f1d1de40b58e803000001f9000000000000da49"); // address
        let (seed, _, _) = words_from_hex("d17096522c1d9de4e3c4c4e8659c1b86")
            .into_components(); // sk seed
        data.append_u32_span(seed.span()); // fors_leaf_addr
        let hash = thash_128s(Default::default(), data.span());
        assert_eq!(hash, [2384795752, 2382117612, 736107028, 3412802428]);
    }
}
