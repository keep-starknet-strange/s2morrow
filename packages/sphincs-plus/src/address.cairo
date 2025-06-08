// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

// Available address implementations.
pub mod dense;
pub mod sparse;

// Default address packing according to the sha256-128s parameters.
#[cfg(not(feature: "sparse_addr"))]
pub use dense::{Address, AddressTrait};

// Cairo-friendly address packing.
#[cfg(feature: "sparse_addr")]
pub use sparse::{Address, AddressTrait};

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
