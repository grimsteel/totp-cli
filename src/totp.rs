use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;

const TIME_STEP_SECS: u64 = 30;

fn get_current_time_steps() -> u64 {
    let now = SystemTime::now();
    let secs = now.duration_since(UNIX_EPOCH).expect("user is in the past").as_secs();
    return secs / TIME_STEP_SECS;
}

fn token_from_time(key: &[u8], time: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("could not create mac");
    let time_bytes = time.to_be_bytes();
    mac.update(&time_bytes);
    let result = mac.finalize().into_bytes();

    // the offset is the 4 lower order bits of the 19th byte
    let offset = (result[19] & 0x0f) as usize;
    let truncated = ((result[offset] & 0x7f) as u32) << 24 |
                    ((result[offset + 1]) as u32) << 16 |
                    ((result[offset + 2]) as u32) << 8 |
                    ((result[offset + 3]) as u32);
    let code = truncated % 1000000;
    return code;
}

pub fn get_current_token(key: &[u8]) -> u32 {
    let time = get_current_time_steps();
    let token = token_from_time(key, time);
    return token;
}
