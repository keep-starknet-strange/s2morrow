// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

use crate::address::{Address, AddressTrait, AddressType};
use crate::fors::{ForsSignature, fors_pk_from_sig};
use crate::hasher::{compute_root, hash_message_128s, initialize_hash_function, thash_128s};
use crate::params_128s::{HashOutput, SPX_D, SPX_DGST_BYTES, SPX_TREE_HEIGHT};
use crate::word_array::{WordArrayTrait, WordSpan, WordSpanTrait};
use crate::wots::{WotsSignature, WotsSignatureDefault, WotsSignatureSerde, wots_pk_from_sig};

#[derive(Drop, Serde, Default)]
pub struct SphincsSignature {
    pub randomizer: HashOutput,
    pub pk_seed: HashOutput,
    pub pk_root: HashOutput,
    pub fors_sig: ForsSignature,
    pub wots_merkle_sig_list: [WotsMerkleSignature; SPX_D],
}

#[derive(Drop, Serde, Default)]
pub struct WotsMerkleSignature {
    pub wots_sig: WotsSignature,
    pub auth_path: [HashOutput; SPX_TREE_HEIGHT - 1],
}

#[derive(Drop)]
pub struct XMessageDigest {
    pub mhash: WordSpan,
    pub tree_address: u64,
    pub leaf_idx: u16,
}

/// Verify a signature for Sphincs+ instantiated with 128s parameters.
pub fn verify_128s(message: WordSpan, sig: SphincsSignature) -> bool {
    let SphincsSignature { randomizer, pk_seed, pk_root, fors_sig, wots_merkle_sig_list } = sig;

    // Seed the hash function state.
    let ctx = initialize_hash_function(pk_seed);

    // Initialize addresses
    let mut tree_addr: Address = Default::default();
    let mut wots_addr: Address = Default::default();
    let mut wots_pk_addr: Address = Default::default();

    tree_addr.set_address_type(AddressType::HASHTREE);
    wots_pk_addr.set_address_type(AddressType::FORSPK);

    // Compute the extended message digest which is `mhash || tree_idx || leaf_idx`.
    let digest = hash_message_128s(randomizer, pk_seed, pk_root, message, SPX_DGST_BYTES);

    // Split the digest into the message hash, tree address and leaf index.
    let XMessageDigest {
        mhash, mut tree_address, mut leaf_idx,
    } = split_xdigest_128s(digest.span());

    wots_addr.set_address_type(AddressType::WOTS);
    wots_addr.set_hypertree_address(tree_address);
    wots_addr.set_keypair(leaf_idx);

    // Compute FORS public key (root) from the signature.
    let mut root = fors_pk_from_sig(ctx, fors_sig, mhash, wots_addr);

    let mut layer: u8 = 0;
    let mut wots_merkle_sig_iter = wots_merkle_sig_list.span();

    while let Some(WotsMerkleSignature { wots_sig, auth_path }) = wots_merkle_sig_iter.pop_front() {
        wots_addr.set_hypertree_address(tree_address);
        wots_addr.set_keypair(leaf_idx);

        // The WOTS public key is only correct if the signature was correct.
        // Initially, root is the FORS pk, but on subsequent iterations it is
        // the root of the subtree below the currently processed subtree.
        let wots_pk = wots_pk_from_sig(ctx, *wots_sig, root, wots_addr);

        wots_pk_addr.set_keypair(leaf_idx);

        // Compute the leaf node using the WOTS public key.
        let leaf = thash_128s(ctx, wots_pk_addr, wots_pk.span());

        tree_addr.set_hypertree_layer(layer);
        tree_addr.set_hypertree_address(tree_address);

        // Compute the root node of this subtree.
        // Auth path has fixed length, so we don't need to assert tree height.
        root = compute_root(ctx, tree_addr, leaf, auth_path.span(), leaf_idx.into(), 0);

        // Update the indices for the next layer.
        let (q, r) = DivRem::div_rem(tree_address, 0x200); // 1 << tree_height = 2^9 = 0x200
        tree_address = q;
        leaf_idx = r.try_into().unwrap();
    }

    // Check if the root node equals the root node in the public key.
    return root == pk_root;
}

/// Split the extended message digest into the message hash, tree address and leaf index.
/// NOTE: this is not a generic implementation, rather a shortcut for 128s.
fn split_xdigest_128s(mut digest: WordSpan) -> XMessageDigest {
    let (mut words, last_word, _) = digest.into_components();

    // Lead index is the 9 LSB of the last word (which is 2 bytes).
    let leaf_idx = last_word % 0x200;
    let leaf_idx: u16 = leaf_idx.try_into().expect('u32 -> u16 cast failed');

    // Tree address is the 54 LSB of the last two words.
    let lo = *words.pop_back().unwrap();
    let ahi = *words.pop_back().unwrap();
    let (a, hi) = DivRem::div_rem(ahi, 0x100000);
    let tree_address = hi.into() * 0x100000000 + lo.into();

    // Message hash is the remaining 21 bytes.
    let mhash = WordSpanTrait::new(words.into(), a / 0x10, 1);

    XMessageDigest { mhash, tree_address, leaf_idx }
}

#[cfg(test)]
mod tests {
    use crate::word_array::WordArrayTrait;
    use crate::word_array::hex::{words_from_hex, words_to_hex};
    use super::*;

    #[test]
    fn test_split_xdigest_128s() {
        let digest = words_from_hex("5f6f74792de379a6337bbad9e4a1621e38c5e3827d8ae84c41501d68e961");
        let xdigest = split_xdigest_128s(digest.span());
        assert_eq!(xdigest.leaf_idx, 0x161);
        assert_eq!(xdigest.tree_address, 0xae84c41501d68);
        assert_eq!(words_to_hex(xdigest.mhash), "5f6f74792de379a6337bbad9e4a1621e38c5e3827d");
    }
}
