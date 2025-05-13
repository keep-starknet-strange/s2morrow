// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! FORS (Forest of Random Subsets) is a few-times signature (FTS) scheme.
//! See https://research.dorahacks.io/2022/12/16/hash-based-post-quantum-signatures-2/ for an overview
//! and https://www.di-mgt.com.au/pqc-09-fors-sig.html for a step-by-step construction.

use crate::params_128s::{SPX_FORS_HEIGHT, SPX_FORS_TREES, HashOutput};
use crate::word_array::{WordSpan, WordSpanTrait};
use core::traits::DivRem;

#[derive(Drop, Copy)]
pub struct ForsSignature {
    pub sig_parts: [ForsSignaturePart; SPX_FORS_TREES],
}

#[derive(Drop, Copy)]
pub struct ForsSignaturePart {
    pub private_key: HashOutput,
    pub auth_path: [HashOutput; SPX_FORS_HEIGHT - 1],
}

/// Derive FORS public key from a signature.
pub fn fors_pk_from_sig(sig: ForsSignature, mhash: WordSpan) -> HashOutput {
    // Compute indices of leaves of the FORS trees
    let indices = message_to_indices_128s(mhash);

    Default::default()
}

/// Convert FORS mhash to leaves indices.
fn message_to_indices_128s(mut mhash: WordSpan) -> Array<u32> {
    let mut indices = array![];

    // Mhash structure (from LSB to MSB): [8] [4 12 12 4] [8 12 12] [12 12 8] [4 12 12 4] [8 12 12]
    // So there are 3 possible cases to handle (for 128s instance).

    let (mut words, mut prev_word, _) = mhash.into_components();
    let mut prev_bits = 8;

    while let Some(word) = words.pop_back() {
        if prev_bits == 8 {
            let (q0, r0) = DivRem::div_rem(*word, 0x10);
            let (q1, r1) = DivRem::div_rem(q0, 0x1000);
            let (q2, r2) = DivRem::div_rem(q1, 0x1000);
            indices.append(r0 * 0x100 + prev_word);
            indices.append(r1);
            indices.append(r2);
            prev_word = q2;
            prev_bits = 4;
        } else if prev_bits == 4 {
            let (q0, r0) = DivRem::div_rem(*word, 0x100);
            let (q1, r1) = DivRem::div_rem(q0, 0x1000);
            indices.append(r0 * 0x10 + prev_word);
            indices.append(r1);
            indices.append(q1);
            prev_word = 0;
            prev_bits = 0;
        } else if prev_bits == 0 {
            let (q0, r0) = DivRem::div_rem(*word, 0x1000);
            let (q1, r1) = DivRem::div_rem(q0, 0x1000);
            indices.append(r0);
            indices.append(r1);
            prev_word = q1;
            prev_bits = 8;
        } else {
            panic!("invalid prev_bits");
        }
    }

    indices
}
