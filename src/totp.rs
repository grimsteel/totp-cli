use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;

// Get the current time step count and the number of seconds left in this one
fn get_current_time_steps(time_step_size: u64) -> (u64, u8) {
    let now = SystemTime::now();
    let secs = now.duration_since(UNIX_EPOCH).expect("user is in the past").as_secs();

    let current_time_step = secs / time_step_size;
    let secs_left = time_step_size - secs % time_step_size;
    (current_time_step, secs_left as u8)
}

fn token_from_time(key: &[u8], time: u64, digits: u8) -> u32 {
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
    let code = truncated % u32::pow(10, digits as u32);
    return code;
}

// Get the current token for a key and the time left
pub fn get_current_token(key: &[u8], time_step_size: u64, digits: u8) -> (u32, u8) {
    let (time_steps, time_left) = get_current_time_steps(time_step_size);
    let token = token_from_time(key, time_steps, digits);
    (token, time_left)
}
