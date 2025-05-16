// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

use crate::params_128s::HashOutput;
use crate::sha2::{Sha256State, sha256_inc_finalize};
use crate::word_array::{WordArray, WordArrayTrait, WordSpan, WordSpanTrait};

/// Compute a truncated hash of the data.
pub fn thash_128s(mut data: WordSpan) -> HashOutput {
    let (input, last_word, last_word_len) = data.into_components();
    let mut state = Sha256State { h: (0, 0, 0, 0, 0, 0, 0, 0), byte_len: 0 };
    let [d0, d1, d2, d3, _, _, _, _] = sha256_inc_finalize(
        ref state, input.into(), last_word, last_word_len,
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
    use super::*;

    #[test]
    fn test_thash_128s() {
        let data = array![
            12061,
            501484376,
            3892510720,
            33095680,
            0,
            3662217216,
            0,
            0,
            3513816658,
            740138468,
            3821323496,
            1704729478,
        ];
        let hash = thash_128s(WordSpanTrait::new(data.span(), 0, 0));
        //assert_eq!(hash, [776494396, 2105697836, 2177691252, 3527764120]);
    }
}
