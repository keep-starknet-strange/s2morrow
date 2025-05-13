// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

/// Hash output length in bytes.
pub const SPX_N: usize = 16;
/// Height of the hypertree.
pub const SPX_FULL_HEIGHT: usize = 63;
/// Number of subtree layer.
pub const SPX_D: usize = 7;
/// FORS tree height.
pub const SPX_FORS_HEIGHT: usize = 12;
/// Number of FORS trees.
pub const SPX_FORS_TREES: usize = 14;

/// Subtree size.
pub const SPX_TREE_HEIGHT: usize = SPX_FULL_HEIGHT / SPX_D; // 9

/// FORS mhash size
pub const SPX_FORS_MSG_BYTES: usize = (SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8; // 21
///
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

/// Hash output.
pub type HashOutput = [u32; 4];
