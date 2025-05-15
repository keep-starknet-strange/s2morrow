// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

use core::blake::{blake2s_compress, blake2s_finalize};
use core::box::BoxImpl;
use crate::word_array::{WordSpan, WordSpanImpl};

const BLAKE2S_256_IV: [u32; 8] = [
    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Blake2s digest.
pub type Blake2sDigest = Box<[u32; 8]>;

/// Compute the 32-byte digest of a message using Blake2s hash function.
/// Message is expected to be a sequence of 4-byte words, padded with zeros if needed.
pub fn blake2s_32(mut data: WordSpan) -> Blake2sDigest {
    let mut state = BoxImpl::new(BLAKE2S_256_IV);
    let mut buffer: Array<u32> = array![];
    let mut byte_count: u32 = 0;

    while let Some((word, num_bytes)) = data.pop_front() {
        // TODO: handle last word
        buffer.append(word);
        byte_count += 4;

        if buffer.len() == 16 {
            let msg = buffer.span().try_into().expect('Cast to @Blake2sInput failed');
            blake2s_compress(state, byte_count, *msg);
        }
    }

    for _ in buffer.len()..16 {
        buffer.append(0);
    }

    let msg = buffer.span().try_into().expect('Cast to @Blake2sInput failed');
    blake2s_finalize(state, byte_count, *msg)
}
