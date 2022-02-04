use core::fmt::Write;
use hex::ToHex;
use std::io;
use std::str;

pub mod hash_func;
pub use crate::hash_func::sha256;

fn main() {
    println!("Please input your string.");

    let mut guess = String::new();

    io::stdin()
        .read_line(&mut guess)
        .expect("Failed to read line");

    let hash = sha256::digest(guess.as_bytes());

    let mut hex_hash = String::with_capacity(2 * hash.len());

    for byte in hash {
        write!(hex_hash, "{:02X}", byte);
    }

    println!("Your hash is:\n{}", hex_hash);
}
