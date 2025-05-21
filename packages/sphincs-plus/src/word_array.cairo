// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT

//! Word array is an alternative to byte array, using a different
//! internal buffer representation, namely Array<u32> instead of
//! Array<byte31>.
//! It allows to avoid costly conversions when preparing inputs for
//! hash function which operates on 4-byte words.

/// Array of 4-byte words where the last word can be partial.
#[derive(Drop, Debug, Serde, Default, PartialEq)]
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
        WordSpan { input, last_input_word, last_input_num_bytes }
    }

    /// Remove one item from the beginning of the [WordSpan] and return
    /// a pair (word, num_bytes) where num_bytes is in range [0; 4].
    /// Returns `Option::None` if the span is empty.
    fn pop_front(ref self: WordSpan) -> Option<(u32, u32)> {
        if let Option::Some(word) = self.input.pop_front() {
            Option::Some((*word, 4))
        } else if self.last_input_num_bytes != 0 {
            let res = (self.last_input_word, self.last_input_num_bytes);
            self.last_input_word = 0;
            self.last_input_num_bytes = 0;
            Option::Some(res)
        } else {
            Option::None
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
        WordArray { input, last_input_word, last_input_num_bytes }
    }

    /// Append a byte.
    fn append_u8(ref self: WordArray, value: u8) {
        if self.last_input_num_bytes == 0 {
            self.last_input_word = value.into();
            self.last_input_num_bytes = 1;
        } else if self.last_input_num_bytes == 1 {
            self.last_input_word = self.last_input_word * 0x100 + value.into();
            self.last_input_num_bytes = 2;
        } else if self.last_input_num_bytes == 2 {
            self.last_input_word = self.last_input_word * 0x100 + value.into();
            self.last_input_num_bytes = 3;
        } else {
            self.input.append(self.last_input_word * 0x100 + value.into());
            self.last_input_word = 0;
            self.last_input_num_bytes = 0;
        }
    }

    /// Append a 4-byte word in big-endian order.
    fn append_u32_be(ref self: WordArray, value: u32) {
        if self.last_input_num_bytes == 0 {
            self.input.append(value)
        } else if self.last_input_num_bytes == 1 {
            let (abc, d) = DivRem::div_rem(value, 0x100);
            self.input.append(self.last_input_word * 0x1000000 + abc);
            self.last_input_word = d;
        } else if self.last_input_num_bytes == 2 {
            let (ab, cd) = DivRem::div_rem(value, 0x10000);
            self.input.append(self.last_input_word * 0x10000 + ab);
            self.last_input_word = cd;
        } else {
            let (a, bcd) = DivRem::div_rem(value, 0x1000000);
            self.input.append(self.last_input_word * 0x100 + a);
            self.last_input_word = bcd;
        }
    }

    /// Append a span of 4-byte words in big-endian order.
    fn append_u32_span(ref self: WordArray, mut span: Span<u32>) {
        while let Option::Some(word) = span.pop_front() {
            self.append_u32_be(*word);
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

#[cfg(or(test, feature: "debug"))]
pub mod hex {
    use core::traits::DivRem;
    use super::{WordArray, WordArrayTrait, WordSpan, WordSpanTrait};

    /// Gets words from hex (base16).
    pub fn words_from_hex(hex_string: ByteArray) -> WordArray {
        let num_characters = hex_string.len();
        assert(num_characters % 2 == 0, 'Invalid hex string length');

        let mut words: WordArray = Default::default();
        let mut i = 0;

        while i != num_characters {
            let hi = hex_char_to_nibble(hex_string[i]);
            let lo = hex_char_to_nibble(hex_string[i + 1]);
            words.append_u8(hi * 16 + lo);
            i += 2;
        }

        words
    }

    /// Converts words to hex (base16).
    pub fn words_to_hex(mut words: WordSpan) -> ByteArray {
        let alphabet: @ByteArray = @"0123456789abcdef";
        let mut result: ByteArray = Default::default();

        while let Option::Some((word, num_bytes)) = words.pop_front() {
            for i in 0..num_bytes {
                let div: NonZero<u32> = match (num_bytes - 1 - i) {
                    0 => 1,
                    1 => 0x100,
                    2 => 0x10000,
                    3 => 0x1000000,
                    _ => panic!("num_bytes out of bounds"),
                };
                let (value, _) = DivRem::div_rem(word, div);
                let (_, value) = DivRem::div_rem(value, 0x100);
                let (l, r) = DivRem::div_rem(value, 16);
                result.append_byte(alphabet.at(l).expect('l'));
                result.append_byte(alphabet.at(r).expect('r'));
            }
        }

        result
    }

    pub fn hex_char_to_nibble(hex_char: u8) -> u8 {
        if hex_char >= 48 && hex_char <= 57 {
            // 0-9
            hex_char - 48
        } else if hex_char >= 65 && hex_char <= 70 {
            // A-F
            hex_char - 55
        } else if hex_char >= 97 && hex_char <= 102 {
            // a-f
            hex_char - 87
        } else {
            panic!("Invalid hex character: {hex_char}");
            0
        }
    }
}
