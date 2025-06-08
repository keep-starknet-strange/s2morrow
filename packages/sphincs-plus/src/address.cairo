// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

// Available address implementations.
mod dense;
mod sparse;
#[cfg(not(feature: "friendly"))]
pub use dense::Address;

// Select the chosen Address implementation
#[cfg(feature: "friendly")]
pub use sparse::Address;
use crate::word_array::WordArray;

#[derive(Drop)]
pub enum AddressType {
    WOTS, // 0
    WOTSPK, // 1
    HASHTREE, // 2
    FORSTREE, // 3
    FORSPK, // 4
    WOTSPRF, // 5
    FORSPRF // 6
}

pub trait AddressTrait<T> {
    fn set_hypertree_layer(ref self: T, layer: u8);
    fn set_hypertree_addr(ref self: T, tree_address: u64);
    fn set_address_type(ref self: T, address_type: AddressType);
    fn set_keypair(ref self: T, keypair: u16);
    fn set_tree_height(ref self: T, tree_height: u8);
    fn set_tree_index(ref self: T, tree_index: u32);
    fn set_wots_chain_addr(ref self: T, chain_address: u8);
    fn set_wots_hash_addr(ref self: T, hash_address: u8);
    fn to_word_array(self: @T) -> WordArray;

    #[cfg(test)]
    fn from_components(components: Array<u32>) -> T;
}

impl AddressTypeToU32 of Into<AddressType, u32> {
    fn into(self: AddressType) -> u32 {
        match self {
            AddressType::WOTS => 0,
            AddressType::WOTSPK => 1,
            AddressType::HASHTREE => 2,
            AddressType::FORSTREE => 3,
            AddressType::FORSPK => 4,
            AddressType::WOTSPRF => 5,
            AddressType::FORSPRF => 6,
        }
    }
}

impl AddressTypeDefault of Default<AddressType> {
    fn default() -> AddressType {
        AddressType::WOTS
    }
}
