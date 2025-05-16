// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

pub mod address;
//pub mod blake2s;
pub mod fors;
pub mod hasher;
pub mod params_128s;
pub mod sha2;
pub mod sphincs;
pub mod word_array;
pub mod wots;

#[executable]
fn main() -> [u32; 8] {
    let mut state: sha2::Sha256State = Default::default();
    sha2::sha256_inc_init(ref state);
    let res = sha2::sha256_inc_finalize(state, array![0, 1, 2, 3, 4, 5, 6, 7, 8], 9, 1);
    let expected = [
        3343000549, 2296934785, 582871359, 984521232, 1002196264, 2637335342, 930443213, 885203535,
    ];
    assert(res == expected, 'aaa');
    res
}
