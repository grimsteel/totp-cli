const ALPHABET: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CHAR_SIZE: i8 = 5;

pub fn validate_base32(raw_input: &str) -> Result<String, String> {
    if !raw_input.is_ascii() {
        return Err("Invalid base32 value: non ascii characters".to_string());
    }

    let uppercase = raw_input.to_uppercase();

    if !uppercase.chars().all(|c| (c >= 'A' &&  c <= 'Z') || (c >= '2' && c <= '7')) {
        return Err("Invalid base32 value: characters out of range".to_string());
    }

    Ok(uppercase)
}

pub fn base32decode(encoded: &str) -> Option<Vec<u8>> {
    // Make sure the data is ascii
    if !encoded.is_ascii() { return None; }

    let chars: Vec<char> = encoded.to_uppercase().chars().collect();
    let decoded_length = chars.len() * CHAR_SIZE as usize / 8; // each b32 char is 5 bits.
    let mut decoded = Vec::with_capacity(decoded_length);

    let mut space_left: i8 = 8;
    let mut leftover: u8 = 0b0;
    
    for c in chars {
        let alphabet_idx = match ALPHABET.find(c) {
            Some(c) => c,
            None => return None
        } as u8;

        // if we're have space for 2, we need to shift _right_ by 3.
        // if we're have space for 8, left by 3 (and zero pad)
        if space_left > CHAR_SIZE {
            let shift_by = space_left - CHAR_SIZE;
            leftover |= alphabet_idx << shift_by;
            space_left -= 5;
        } else {
            let shift_by = CHAR_SIZE - space_left;
            leftover |= alphabet_idx >> shift_by;

            // we filled up a chra
            decoded.push(leftover);
            space_left = 8 - shift_by;

            // we had more from the current char
            if space_left < 8 {
                leftover = alphabet_idx << space_left;
            } else {
                leftover = 0;
            }
        }
    }    

    return Some(decoded);
}

#[test]
fn test_hello() {
    assert_eq!(Ok("Hello, world!".to_string()), String::from_utf8(base32decode("JBSWY3DPFQQHO33SNRSCC").unwrap()));
}

#[test]
fn test_lowercase() {
    assert_eq!(Ok("lowercase".to_string()), String::from_utf8(base32decode("nrxxozlsmnqxgzi").unwrap()));
}

#[test]
fn test_error() {
    assert_eq!(None, base32decode("!!!"));
}
