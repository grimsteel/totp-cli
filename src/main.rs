mod base32;
mod totp;

use crate::base32::base32decode;
use crate::totp::get_current_token;

pub fn main() {
    let token = "";
    let decoded_token = base32decode(token).expect("oops!");
    let current_code = get_current_token(&decoded_token);
    println!("{}", current_code);
}
