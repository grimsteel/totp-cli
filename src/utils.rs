use std::{io::{self, stdin, IsTerminal, stdout, BufRead, BufReader, Write, Error as IoError}, fs::File, os::fd::AsRawFd, mem::MaybeUninit};

use libc::{termios, tcgetattr, ECHO, ECHONL, tcsetattr, TCSANOW};
use url::Url;

use crate::{secret_storage::TokenInfo, base32::validate_base32};

pub fn parse_otpauth_uri(raw_uri: &str) -> Result<TokenInfo, String> {
    let uri = Url::parse(raw_uri).map_err(|_| "Invalid uri")?;
    // Get all of the relevant things out of the url
    let scheme = uri.scheme();
    let domain = uri.domain();
    let path = uri.path().strip_prefix("/").ok_or("path starts with '/'")?;
    let token = uri.query_pairs().find(|p| p.0 == "secret");
    let issuer = match uri.query_pairs().find(|p| p.0 == "issuer") {
        Some(i) => i.1.to_string(),
        // Could also be in the path
        _ => path.split(":").next().unwrap_or("").to_string()
    };

    match (scheme, domain, token) {
        ("otpauth", Some("totp"), Some((_, token))) => {
            let token = validate_base32(&token)?;
            Ok(TokenInfo {
                label: path.to_string(),
                issuer,
                token
            })
        },
        _ => Err("Invalid otpauth uri".to_string())
    }
}

pub fn get_hidden_input(prompt: &str) -> io::Result<String> {
    let mut buf = String::new();
    
    if stdin().is_terminal() {    
        print!("{}", prompt);
        stdout().flush()?;
        
        let tty = File::open("/dev/tty")?;
        let fd = tty.as_raw_fd();
        let mut orig_termios: MaybeUninit<termios> = MaybeUninit::uninit();

        // Disable echo
        unsafe {
            if tcgetattr(fd, orig_termios.as_mut_ptr()) != 0 {
                return io::Result::Err(IoError::last_os_error());
            }
            let mut cur_termios = orig_termios.clone().assume_init();
            // Disable all echo except for a newline
            cur_termios.c_lflag &= !ECHO;
            cur_termios.c_lflag |= ECHONL;

            if tcsetattr(fd, TCSANOW, &cur_termios) != 0 {
                return io::Result::Err(IoError::last_os_error());
            }
        }
        
        let mut reader = BufReader::new(tty);
        
        reader.read_line(&mut buf)?;

        // Restore previous settings
        unsafe {
            if tcsetattr(fd, TCSANOW, &orig_termios.assume_init()) != 0 {
                return io::Result::Err(IoError::last_os_error());
            }
        }
    } else {
        // If this is not a terminal, just read from stdin normally
        stdin().read_line(&mut buf)?;
    }

    // Remove the trailing newline
    buf.pop();

    io::Result::Ok(buf)
}
