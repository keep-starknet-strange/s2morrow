// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! Word array is an alternative to byte array, using a different
//! internal buffer representation, namely Array<u32> instead of
//! Array<byte31>.
//! It allows to avoid costly conversions when preparing inputs for
//! hash function which operates on 4-byte words.

/// Array of 4-byte words where the last word can be partial.
#[derive(Drop, Debug, Default, PartialEq)]
pub struct WordArray {
    input: Array<u32>,
    last_input_word: u32,
    last_input_num_bytes: u32,
}

/// Span of a [WordArray]
#[derive(Copy, Drop, Debug, PartialEq)]
pub struct WordSpan {
    input: Span<u32>,
    last_input_word: u32,
    last_input_num_bytes: u32,
}

#[generate_trait]
pub impl WordSpanImpl of WordSpanTrait {
    /// Create a new [WordSpan] from components.
    fn new(input: Span<u32>, last_input_word: u32, last_input_num_bytes: u32) -> WordSpan {
        WordSpan {
            input,
            last_input_word,
            last_input_num_bytes,
        }
    }

    /// Split word array into components:
    /// (array of full 4-byte words, last word, number of bytes in the last word)
    fn into_components(self: WordSpan) -> (Span<u32>, u32, u32) {
        (self.input, self.last_input_word, self.last_input_num_bytes)
    }
}

#[generate_trait]
pub impl WordArrayImpl of WordArrayTrait {
    /// Create a new [WordArray] from components.
    fn new(input: Array<u32>, last_input_word: u32, last_input_num_bytes: u32) -> WordArray {
        WordArray {
            input,
            last_input_word,
            last_input_num_bytes,
        }
    }

    /// Create a [WordSpan] out of the array snapshot.
    fn span(self: @WordArray) -> WordSpan {
        WordSpan {
            input: self.input.span(),
            last_input_word: *self.last_input_word,
            last_input_num_bytes: *self.last_input_num_bytes,
        }
    }

    /// Split word array into components:
    /// (array of full 4-byte words, last word, number of bytes in the last word)
    fn into_components(self: WordArray) -> (Array<u32>, u32, u32) {
        (self.input, self.last_input_word, self.last_input_num_bytes)
    }

    /// Calculate array length in bytes
    fn byte_len(self: @WordArray) -> usize {
        self.input.len() * 4 + *self.last_input_num_bytes
    }
}
