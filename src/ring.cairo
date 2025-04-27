use core::num::traits::CheckedAdd;

pub const Q: u16 = 12289;
pub const QQ: i16 = 12289;
pub const Q32: u32 = 12289;
pub const Q64: u64 = 12289;

/// Add two values modulo Q
pub fn add_mod(a: u16, b: u16) -> u16 {
    a.checked_add(b).expect('u16 add overflow') % Q
}

/// Subtract two values modulo Q
pub fn sub_mod(a: u16, b: u16) -> u16 {
    (a.checked_add(Q).expect('u16 + Q overflow') - b) % Q
}

/// Multiply two values modulo Q
pub fn mul_mod(a: u16, b: u16) -> u16 {
    let a: u32 = a.into();
    let b: u32 = b.into();
    let res = (a * b) % Q32;
    res.try_into().unwrap()
}

/// Multiply three values modulo Q
pub fn mul3_mod(a: u16, b: u16, c: u16) -> u16 {
    let a: u64 = a.into();
    let b: u64 = b.into();
    let c: u64 = c.into();
    let res = (a * b * c) % Q64;
    res.try_into().unwrap()
}
