// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! FORS (Forest of Random Subsets) is a few-times signature (FTS) scheme.
//! See https://research.dorahacks.io/2022/12/16/hash-based-post-quantum-signatures-2/ for an
//! overview and https://www.di-mgt.com.au/pqc-09-fors-sig.html for a step-by-step construction.

use core::traits::DivRem;
use crate::address::{Address, AddressTrait, AddressType};
use crate::hasher::thash_128s;
use crate::params_128s::{HashOutput, SPX_FORS_BASE_OFFSET, SPX_FORS_HEIGHT, SPX_FORS_TREES};
use crate::word_array::{WordArrayTrait, WordSpan, WordSpanTrait};

#[derive(Drop, Copy)]
pub struct ForsSignature {
    pub tree_sigs: [ForsTreeSignature; SPX_FORS_TREES],
}

#[derive(Drop, Copy)]
pub struct ForsTreeSignature {
    pub sk_seed: HashOutput,
    pub auth_path: [HashOutput; SPX_FORS_HEIGHT - 1],
}

/// Derive FORS public key from a signature.
pub fn fors_pk_from_sig(sig: ForsSignature, mhash: WordSpan, address: Address) -> HashOutput {
    let mut fors_pk_addr = address;
    let mut fors_tree_addr = address;

    fors_pk_addr.set_address_type(AddressType::FORSPK);
    fors_tree_addr.set_address_type(AddressType::FORSTREE);

    // Compute indices of leaves of the FORS trees
    let mut indices = message_to_indices_128s(mhash);
    // Offset for the leaves indices
    let mut idx_offset = 0;

    for fors_tree_sig in sig.tree_sigs.span() {
        let ForsTreeSignature { sk_seed, auth_path } = *fors_tree_sig;
        let leaf_idx = indices.pop_front().unwrap();

        fors_tree_addr.set_fors_tree_height(0);
        fors_tree_addr.set_fors_tree_index(idx_offset + leaf_idx);

        // Derive the leaf hash from the secret key seed and tree address.
        let leaf_hash = fors_sk_to_leaf(sk_seed, fors_tree_addr);

        // Derive the corresponding root node of this tree.
        // compute_root(
        //     &mut roots[i*SPX_N..], &leaf, indices[i], idx_offset,
        //     &sig[idx..], SPX_FORS_HEIGHT as u32, ctx, &mut fors_tree_addr
        // );

        idx_offset += SPX_FORS_BASE_OFFSET;
    }

    Default::default()
}

/// Compute the leaf from the revealed secret key (which is part of the signature) and tree address.
pub fn fors_sk_to_leaf(sk_seed: HashOutput, address: Address) -> HashOutput {
    let mut input = address.to_array();
    input.append_span(sk_seed.span());
    thash_128s(WordSpanTrait::new(input.span(), 0, 0))
}

/// Convert FORS mhash to leaves indices.
///
/// A simplified flow:
/// - reinterpret mhash as a little-endian integer
/// - calculate SPX_FORS_TREES remainders modulo SPX_FORS_HEIGHT
///
/// In other words, we are iterating over the mhash in reverse byte order,
/// interpreting every SPX_FORS_HEIGHT chunk of bits as a little-endian integer.
fn message_to_indices_128s(mut mhash: WordSpan) -> Array<u32> {
    let mut indices = array![];

    // Accumulator is the LSB "carry" from the previous word.
    let mut acc = 0;
    let mut acc_bits = 0;

    // Mhash structure: words are byte-reversed, we are going in LE order.
    // [8|4 4|8, 8] [4 4|8 8|4, 4] [8 8|4 4|8] [8|4 4|8, 8] [4 8|4 4|8, 4] [8]
    while let Some((mut word, num_bytes)) = mhash.pop_front() {
        if num_bytes == 4 {
            // Our word [ab cd ef gh] is in BE, we need to decompose it into bytes
            let (ab, cdefgh) = DivRem::div_rem(word, 0x1000000);
            let (cd, efgh) = DivRem::div_rem(cdefgh, 0x10000);
            let (ef, gh) = DivRem::div_rem(efgh, 0x100);

            if acc_bits == 0 { // [dab efc, gh]
                let (c, d) = DivRem::div_rem(cd, 0x10);
                indices.append(d * 0x100 + ab);
                indices.append(ef * 0x10 + c);
                acc = gh;
                acc_bits = 8;
            } else if acc_bits == 8 { // [bxx cda hef, g]
                let (a, b) = DivRem::div_rem(ab, 0x10);
                let (g, h) = DivRem::div_rem(gh, 0x10);
                indices.append(b * 0x100 + acc);
                indices.append(cd * 0x10 + a);
                indices.append(h * 0x100 + ef);
                acc = g;
                acc_bits = 4;
            } else if acc_bits == 4 { // [abx fcd ghe]
                let (e, f) = DivRem::div_rem(ef, 0x10);
                indices.append(ab * 0x10 + acc);
                indices.append(f * 0x100 + cd);
                indices.append(gh * 0x10 + e);
                acc = 0;
                acc_bits = 0;
            } else {
                assert(false, 'invalid acc_bits (4)');
            }
        } else if num_bytes == 1 { // [abx]
            // Last word is one byte (lowest)
            assert(acc_bits == 4, 'invalid acc_bits (1)');
            indices.append(word * 0x10 + acc);
        } else {
            assert(false, 'invalid mhash length');
        }
    }

    indices
}

#[cfg(test)]
mod tests {
    use crate::word_array::WordArrayTrait;
    use crate::word_array::hex::words_from_hex;
    use super::*;

    #[test]
    fn test_message_to_indices_128s() {
        let mhash = words_from_hex("6059c80500bb1e198b352d9edde57e7550ccc7a97e");
        assert_eq!(mhash.byte_len(), 21);
        let indices = message_to_indices_128s(mhash.span());
        let expected = array![
            2400, 3205, 5, 2992, 2334, 2225, 3381, 2530, 1501, 2030, 117, 3269, 2503, 2026,
        ];
        assert_eq!(expected, indices);
    }
}
