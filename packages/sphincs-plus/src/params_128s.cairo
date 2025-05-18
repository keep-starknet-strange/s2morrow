// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

/// Hash output length in bytes.
pub const SPX_N: usize = 16;
/// Hash output length in words.
pub const SPX_HASH_LEN: usize = 4;
/// Height of the hypertree.
pub const SPX_FULL_HEIGHT: usize = 63;
/// Number of subtree layer.
pub const SPX_D: usize = 7;
/// FORS tree height.
pub const SPX_FORS_HEIGHT: usize = 12;
/// FORS tree base offset: 1 << SPX_FORS_HEIGHT.
pub const SPX_FORS_BASE_OFFSET: usize = 4096;
/// Number of FORS trees.
pub const SPX_FORS_TREES: usize = 14;
/// Subtree size.
pub const SPX_TREE_HEIGHT: usize = SPX_FULL_HEIGHT / SPX_D; // 9
/// FORS mhash size
pub const SPX_FORS_MSG_BYTES: usize = (SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8; // 21
/// FORS signature size
pub const SPX_FORS_BYTES: usize = (SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N;
/// Hypertree address bit length.
pub const SPX_TREE_BITS: usize = SPX_TREE_HEIGHT * (SPX_D - 1); // 54
/// Hypertree address byte length.
pub const SPX_TREE_BYTES: usize = (SPX_TREE_BITS + 7) / 8; // 7
/// Bottom leaf index bit length.
pub const SPX_LEAF_BITS: usize = SPX_TREE_HEIGHT; // 9
/// Bottom leaf index byte length.
pub const SPX_LEAF_BYTES: usize = (SPX_LEAF_BITS + 7) / 8; // 2
/// Extended message digest length.
pub const SPX_DGST_BYTES: usize = SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES; // 30
/// WOTS+ word size
pub const SPX_WOTS_W: usize = 16;
/// WOTS+ log word size
pub const SPX_WOTS_LOGW: usize = 4;
/// WOTS+ W-encoded message length.
pub const SPX_WOTS_LEN1: usize = 8 * SPX_N / SPX_WOTS_LOGW; // 32
/// WOTS+ W-encoded checksum length.
pub const SPX_WOTS_LEN2: usize = 3;
/// WOTS+ total length.
pub const SPX_WOTS_LEN: usize = SPX_WOTS_LEN1 + SPX_WOTS_LEN2; // 35

