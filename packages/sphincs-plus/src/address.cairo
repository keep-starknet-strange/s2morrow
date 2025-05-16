// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! Address structure aligned for use with SHA2/Blake2s hash functions.
//! See https://www.di-mgt.com.au/pqc-09-fors-sig.html for layout details.

/// FORS address layout:
///  0       4      8        12       16       20
/// [0 111] [1111] [1 2 xx] [3 3 xx] [x 4 55] [55 xx]
///
/// WOTS address layout:
///  0       4      8        12       16       20
/// [0 111] [1111] [1 2 xx] [3 3 xx] [x 6 xx] [x 7 xx]
///
/// Where:
/// 0. Hypertree layer (1 byte)
/// 1. Hypertree address (8 bytes)
/// 2. Address type (1 byte)
/// 3. Keypair hi/lo (2 bytes)
/// 4. Forst tree height (1 byte)
/// 5. Forst tree index (4 bytes)
/// 6. Wots chain address (1 byte)
/// 7. Wots hash address (1 byte)
#[derive(Drop, Copy, Default)]
pub struct Address {
    w0: u32, // layer, hypertree address
    w1: u32, // hypertree address 
    w2: u32, // hypertree address, address type
    w3: u32, // keypair high/low bytes
    w4: u32, // forst tree height | wots chain address
    w5: u32, // forst tree index | wots hash address
    // Cached values
    w0_a: u32,
    w0_bcd: u32,
    w2_a: u32,
    w2_b: u32,
    w4_b: u32,
    w4_cd: u32,
}

#[derive(Drop, Copy)]
pub enum AddressType {
    WOTS, // 0
    WOTSPK, // 1
    HASHTREE, // 2
    FORSTREE, // 3
    FORSPK, // 4
    WOTSPRF, // 5
    FORSPRF // 6
}

#[generate_trait]
pub impl AddressImpl of AddressTrait {
    fn set_hypertree_layer(ref self: Address, layer: u8) {
        self.w0_a = layer.into() * 0x1000000;
        self.w0 = self.w0_a + self.w0_bcd;
    }

    fn set_hypertree_address(ref self: Address, tree_address: u64) {
        let (abc, defgh) = DivRem::div_rem(tree_address, 0x10000000000);
        let (defg, h) = DivRem::div_rem(defgh, 0x100);
        self.w0_bcd = abc.try_into().unwrap();
        self.w0 = self.w0_a + self.w0_bcd;
        self.w1 = defg.try_into().unwrap();
        self.w2_a = h.try_into().unwrap() * 0x1000000;
        // we don't care about the lowest 2 bytes (they are not used and set to zero)
        self.w2 = self.w2_a + self.w2_b;
    }

    fn set_address_type(ref self: Address, address_type: AddressType) {
        self.w2_b = address_type.into() * 0x10000;
        // we don't care about the lowest 2 bytes (they are not used and set to zero)
        self.w2 = self.w2_a + self.w2_b;
    }

    fn set_keypair(ref self: Address, keypair: u16) {
        // we don't care about the lowest 2 bytes (they are not used and set to zero)
        self.w3 = keypair.into() * 0x10000;
    }

    fn set_fors_tree_height(ref self: Address, tree_height: u8) {
        self.w4_b = tree_height.into() * 0x10000;
        // we don't care about the highest byte (it is not used and set to zero)
        self.w4 = self.w4_b + self.w4_cd;
    }

    fn set_fors_tree_index(ref self: Address, tree_index: u32) {
        let (ab, cd) = DivRem::div_rem(tree_index, 0x10000);
        self.w4_cd = ab;
        // we don't care about the highest byte (it is not used and set to zero)
        self.w4 = self.w4_b + self.w4_cd;
        // we don't care about the lowest 2 bytes (they are not used and set to zero)
        self.w5 = cd * 0x10000;
    }

    fn to_array(self: Address) -> Array<u32> {
        // NOTE: we add two trailing zero words
        array![self.w0, self.w1, self.w2, self.w3, self.w4, self.w5, 0, 0]
    }
}

impl AddressTypeDefault of Default<AddressType> {
    fn default() -> AddressType {
        AddressType::WOTS
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fors_tree_address() {
        let mut address: Address = Default::default();
        address.set_hypertree_layer(0);
        address.set_hypertree_address(14512697849565227);
        address.set_address_type(AddressType::FORSTREE);
        address.set_keypair(102);
        address.set_fors_tree_height(0);
        address.set_fors_tree_index(2765);
        let array = address.to_array();
        let expected = array![13199, 952634960, 721616896, 6684672, 0, 181207040, 0, 0];
        assert_eq!(array, expected);
    }
}
