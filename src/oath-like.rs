use clap::Parser;

use base32::base32decode;
use totp::get_current_token;

mod base32;
mod totp;

/// Partial oathtool-compatible mock
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// use base32 encoding of KEY instead of hex
    #[arg(short, long)]
    base32: bool,
    /// time-step duration
    #[arg(short, long, default_value_t = 30)]
    time_step_size: u8,
    /// number of digits in one-time password
    #[arg(short, long, default_value_t = 6)]
    digits: u8,

    key: String
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.is_ascii() || hex.len() % 2 != 0 {
        return None;
    }

    hex.chars().enumerate().step_by(2).map(
        |(i, _c)| u8::from_str_radix(&hex[i..i + 2], 16).ok()
    ).collect()
}

fn main() {
    let cli = Cli::parse();

    let key = if cli.base32 { base32decode(&cli.key) } else { decode_hex(&cli.key) };

    match key {
        Some(key) => {
            println!("{:01$}", get_current_token(&key, cli.time_step_size as u64, cli.digits).0, cli.digits as usize);
        },
        None => {
            eprintln!("Invalid key format");
        }
    }
}
